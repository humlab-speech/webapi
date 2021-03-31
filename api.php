<?php
require 'vendor/autoload.php';
require 'SessionManagerInterface.class.php';
require_once 'ApiResponse.class.php';

use GuzzleHttp\Psr7;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ClientException;
use MongoDB\Client;


$domain = getenv("HS_DOMAIN_NAME");
session_set_cookie_params(60*60*8, "/", ".".$domain);
session_start();

$gitlabAddress = "http://gitlab:80";
$gitlabAccessToken = getenv("GIT_API_ACCESS_TOKEN");
$hsApiAccessToken = getenv("HS_API_ACCESS_TOKEN");
$logLevel = getenv("LOG_LEVEL");


class Application {
    function __construct() {
        global $hsApiAccessToken;
        $this->sessionManagerInterface = new SessionManagerInterface($this, $hsApiAccessToken);
    }

    function route() {
        if(empty($_SESSION['authorized']) || $_SESSION['authorized'] !== true) {
            //if user has not passed a valid authentication, don't allow access to this API
            $this->addLog("User not signed in - Authorization required");
            $ar = new ApiResponse(401, "Authorization required");
            echo $ar->toJSON();
            exit();
        }

        $reqPath = $_SERVER['REQUEST_URI'];
        $reqMethod = $_SERVER['REQUEST_METHOD'];
        
        if($reqMethod == "GET") {
            switch($reqPath) {
                case "/api/v1/personalaccesstoken":
                    $this->addLog("GET: /api/v1/personalaccesstoken");
                    $apiResponse = $this->getPersonalAccessToken();
                break;
                case "/api/v1/user":
                    $this->addLog("GET: /api/v1/user");
                    $apiResponse = $this->getGitlabUser();
                break;
                case "/api/v1/session":
                    $this->addLog("GET: /api/v1/session");
                    $this->addLog("cwd: ".getcwd());
                    $apiResponse = $this->getUserSessionAttributes();
                break;
                case "/api/v1/user/project":
                    $this->addLog("GET: /api/v1/user/project");
                    $apiResponse = $this->getGitlabUserProjects();
                break;
                case "/api/v1/signout":
                    $this->addLog("GET: /api/v1/signout");
                    $apiResponse = $this->signOut();
                break;
            }

            if($apiResponse !== false) {
                return $apiResponse->toJSON();
            }
        }
        
        if($reqMethod == "POST") {
            $postData = [];
            if(!empty($_POST['data'])) {
                $postData = json_decode($_POST['data']);
            }
        
            switch($reqPath) {
                case "/api/v1/upload":
                    $this->addLog("POST: /api/v1/upload");
                    $apiResponse = $this->handleUpload();
                break;
                case "/api/v1/personalaccesstoken":
                    $this->addLog("POST: /api/v1/personalaccesstoken");
                    $apiResponse = $this->createPersonalAccessToken();
                break;
                case "/api/v1/user":
                    $this->addLog("POST: /api/v1/user");
                    $apiResponse = $this->createGitlabUser();
                break;
                case "/api/v1/user/project":
                    $this->addLog("POST: /api/v1/user/project");
                    //TODO: Perhaps verify that this user has the right to create a new project?
                    $apiResponse = $this->createProject($postData);
                break;
                case "/api/v1/rstudio/session/please":
                    $this->addLog("POST: /api/v1/rstudio/session/please");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $apiResponse = $this->sessionManagerInterface->fetchSession($postData->projectId, "rstudio");
                    }
                    else {
                        $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                    }
                break;
                case "/api/v1/jupyter/session/please":
                    $this->addLog("POST: /api/v1/jupyter/session/please");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $apiResponse = $this->sessionManagerInterface->fetchSession($postData->projectId, "jupyter");
                    }
                    else {
                        $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                    }
                break;
                case "/api/v1/emuwebapp/session/please":
                    $this->addLog("POST: /api/v1/emuwebapp/session/please");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $apiResponse = new ApiResponse(200, array('personalAccessToken' => $_SESSION['personalAccessToken']));
                    }
                    else {
                        $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                    }
                break;
                case "/api/v1/session/save":
                    $this->addLog("POST: /api/v1/session/save");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $apiResponse = $this->sessionManagerInterface->commitSession($postData->sessionId);
                    }
                break;
                case "/api/v1/session/close":
                    $this->addLog("POST: /api/v1/session/close");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $apiResponse = $this->sessionManagerInterface->delSession($postData->sessionId);
                    }
                break;
                case "/api/v1/user/project/delete":
                    $this->addLog("POST: /api/v1/user/project/delete");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $apiResponse = $this->deleteGitlabProject($postData->projectId);
                    }
                    else {
                        $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                    }
                break;
            }
            return $apiResponse->toJSON();
        }
    }

    function getMongoPatCollection() {
        $mongoPass = getenv("MONGO_ROOT_PASSWORD");
        $client = new Client("mongodb://root:".$mongoPass."@mongo");
        $database = $client->selectDatabase('humlab_speech');
        $collection = $database->selectCollection('personal_access_tokens');
        return $collection;
    }

    function savePersonalAccessTokenToStorage($userId, $pat) {
        $coll = $this->getMongoPatCollection();
        $coll->deleteMany(['userId' => $userId]);
        $result = $coll->insertOne([
            'userId' => $userId,
            'pat' => $pat
        ]);
        return $result;
    }

    function getPersonalAccessTokenFromStorage($userId) {
        $this->addLog("getPersonalAccessTokenFromStorage ".$userId);
        $coll = $this->getMongoPatCollection();
        $result = $coll->findOne(['userId' => $userId]);

        if($result == null) {
            return false;
        }

        return $result->jsonSerialize();
    }

    function httpRequest($method = "GET", $url, $options = []) {
        $this->addLog("Http Request: ".$method." ".$url);
        //$this->addLog(print_r($options, true), "debug");
        $httpClient = new GuzzleHttp\Client();
    
        $exception = false;
        $response = "";

        try {
            switch(strtolower($method)) {
                case "get":
                    $response = $httpClient->request('GET', $url, $options);
                    break;
                case "delete":
                    $response = $httpClient->request('DELETE', $url, $options);
                    break;
                case "post":
                    $response = $httpClient->request('POST', $url, $options);
                    break;
                case "put":
                    $response = $httpClient->request('PUT', $url, $options);
                    break;
            }
        }
        catch(ConnectException $e) {
            $exception = $e;
            $this->addLog("Connect exception!", "error");
            $this->addLog("req:".$e->getRequest()->getMethod()." ".$e->getRequest()->getUri(), "error");
            return false;
        }
        catch(ClientException $e) {
            $exception = $e;
            $this->addLog("Client exception! HTTP ".$e->getResponse()->getStatusCode()." ".$e->getResponse()->getReasonPhrase(), "error");
            $this->addLog("req:".$e->getRequest()->getMethod()." ".$e->getRequest()->getUri(), "error");
            $this->addLog("msg:".$e->getResponse()->getBody(), "error");
            return false;
        }
        catch(Exception $e) {
            $exception = $e;
            $this->addLog("Other exception! HTTP ".$e->getResponse()->getStatusCode()." ".$e->getResponse()->getReasonPhrase(), "error");
            $this->addLog("req:".$e->getRequest()->getMethod()." ".$e->getRequest()->getUri(), "error");
            $this->addLog("msg:".$e->getResponse()->getBody(), "error");
            return false;
        }
    
        $ret = [];
    
        if($exception !== false) {
            //This contains the gitlab root key - very sensitive info - redacting the key here
            $exceptionOutput = preg_replace("/private_token=.[A-Za-z0-9_-]*/", "/private_token=REDACTED", $exception);
            $ret['body'] = $exceptionOutput;
        }
        else {
            if(is_object($response)) {
                $ret['body'] = $response->getBody()->getContents();
            }
            else {
                $ret['body'] = $response;
            }
        }
    
        if(is_object($response)) {
            $ret['code'] = $response->getStatusCode();
        }
    
        return $ret;
    }
    
    function userHasProjectAuthorization($projectId) {
        global $gitlabAddress, $gitlabAccessToken, $gitlabUser;
    
        $arProjects = $this->getGitlabUserProjects();
        $projects = json_decode($arProjects)->body;
    
        $foundProject = false;
        foreach($projects as $key => $project) {
            if($project->id == $projectId) {
                $foundProject = true;
            }
        }
        if(!$foundProject) {
            $this->addLog("User attempted to access unauthorized project.", "warn");
            $this->addLog(print_r($gitlabUser, true), "debug");
        }
        return $foundProject;
    }
    
    function handleUpload() {
        $this->addLog("handleUpload", "debug");
        $data = json_decode($_POST['data']);
        $this->addLog("Received upload request of file with filename '".$data->filename."'");
        $fileData = $data->file;
        $fileName = $this->sanitize($data->filename);
        $sessionName = $this->sanitize($data->session);
        $this->addLog("Post-sanitization filename: ".$fileName);
        $this->addLog("Post-sanitization sessionName: ".$sessionName);

        //file data looks like: data:audio/wav;base64,UklGRoQuFgBXQVZFZm10IBAAAAABAAEAgLsAAAB3AQACABAA
        $pos = strpos($fileData, ";base64,");
        $mime = substr($fileData, 5, $pos);
        $this->addLog("Reported mime-type of file is: ".$mime);
        $fileDataWithoutMime = substr($fileData, $pos+8);

        $fileDataWithoutMime = str_replace(' ','+',$fileDataWithoutMime);
        $fileBinary = base64_decode($fileDataWithoutMime, true);
        $this->addLog("File size of ".$fileName." is ".strlen($fileBinary)." bytes");

        $targetDir = "/tmp/uploads/".$_SESSION['gitlabUser']->id."/".$data->context."/".$sessionName;

        $this->addLog("File destination: ".$targetDir);
        
        $this->createDirectory($targetDir);

        file_put_contents($targetDir."/".$fileName, $fileBinary);

        $ar = new ApiResponse(200);
        return $ar;
    }

    function createDirectory($targetDir) {
        if(!is_dir($targetDir)) {
            umask(0);
            $mkdirResult = mkdir($targetDir, 0777, true);
            if(!$mkdirResult) {
                $this->addLog("Failed creating upload destination! : ".$targetDir." As user: ".get_current_user()." (".getmyuid().")", "error");
            }
            return $mkdirResult;
        }
        return true;
    }
    
    function signOut() {
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
        header("Location: https://".$_SERVER['HTTP_HOST']);

        return false;
    }
    
    function getGitLabUsername($email) {
        return str_replace("@", "_at_", $email);
    }
    
    function addLog($msg, $level = "info") {
        global $logLevel;
        if($level == "debug" && $logLevel != "debug") {
            return;
        }

        if(is_object($msg)) {
            $msg = serialize($msg);
        }

        file_put_contents("/var/log/api/webapi.log", date("Y-m-d H:i:s")." [".strtoupper($level)."] ".$msg."\n", FILE_APPEND);
    }
    
    function getUserSessionAttributes() {

        if(empty($_SESSIN['gitlabUser'])) {
            $this->getGitlabUser();
        }

        //If we don't have a PAT yet, fetch it now
        if(empty($_SESSION['personalAccessToken'])) {
            $response = $this->getPersonalAccessToken();
            if($response->code == 200) {
                $_SESSION['personalAccessToken'] = $response->body;
            }
        }

        $output = [
            'firstName' => $_SESSION['firstName'],
            'lastName' => $_SESSION['lastName'],
            'fullName' => $_SESSION['firstName']." ".$_SESSION['lastName'],
            'email' => $_SESSION['email'],
            'gitlabUsername' => $this->getGitLabUsername($_SESSION['email']),
            'personalAccessToken' => $_SESSION['personalAccessToken']
        ];
    
        return new ApiResponse(200, $output);
    }
    
    function createGitlabUser() {
        global $gitlabAddress, $gitlabAccessToken;
        
        $gitlabUsername = $this->getGitLabUsername($_SESSION['email']);
        $gitlabApiRequest = $gitlabAddress."/api/v4/users?username=".$gitlabUsername."&private_token=".$gitlabAccessToken;
    
        $options = [
            'form_params' => [
                'email' => $_SESSION['email'],
                'name' => $_SESSION['firstName']." ".$_SESSION['lastName'],
                'username' => $gitlabUsername,
                'force_random_password' => '1',
                'reset_password' => 'false',
                'skip_confirmation' => true,
                'provider' => $_SESSION['Shib-Identity-Provider']
            ]
        ];
    
        $response = $this->httpRequest("POST", $gitlabApiRequest, $options); 
    
        if($response['code'] == 201) {
            $userApiResponseObject = json_decode($this->getGitlabUser());
            $gitlabUser = $userApiResponseObject->body;
            $ar = new ApiResponse($response['code'], $gitlabUser);
        }
        else {
            $ar = new ApiResponse($response['code'], $response['body']);
        }
    
        return $ar;
    }

    function deleteAllPersonalAccessTokens($onlySystemTokens = true) {
        $this->addLog("deleteAllPersonalAccessTokens");
        $ar = $this->fetchPersonalAccessTokens();
        if($ar->code != 200) {
            $this->addLog("Not deleting personal access tokens, because return code on fetching list of tokens was ".$ar->code);
            return false;
        }
        $tokenList = json_decode($ar->body);
        $this->addLog(print_r($tokenList, true));
        $responses = [];
        foreach($tokenList as $token) {
            if(($onlySystemTokens && $token->name == "Humlab Speech System Token") || $onlySystemTokens === false) {
                $ar = $this->deletePersonalAccessToken($token->id);
                $responses []= $ar;

                if($ar->code != 204) {
                    $this->addLog("Received non-expected HTTP code ".$ar->code." when deleting PAT ".$token->id.". Expected code 204", "error");
                }
            }
        }

        $this->addLog("deleteAllPersonalAccessTokens result: ".print_r($responses, true), "debug");
        return $responses;
    }

    function deletePersonalAccessToken($tokenId) {
        global $gitlabAddress, $gitlabAccessToken;
        $gitlabApiRequest = $gitlabAddress."/api/v4/personal_access_tokens/".$tokenId."?private_token=".$gitlabAccessToken;
        $response = $this->httpRequest("DELETE", $gitlabApiRequest);
        return new ApiResponse($response['code'], $response['body']);
    }

    function fetchPersonalAccessTokens() {
        global $gitlabAddress, $gitlabAccessToken;
        $gitlabApiRequest = $gitlabAddress."/api/v4/personal_access_tokens?user_id=".$_SESSION['gitlabUser']->id."&private_token=".$gitlabAccessToken;
        $response = $this->httpRequest("GET", $gitlabApiRequest);

        $this->addLog("Fetch PAT response: ".print_r($response, true), "debug");

        $ar = new ApiResponse($response['code'], $response['body']);
        return $ar;
    }

    /**
     * Function: getPersonalAccessToken
     * 
     * This first tries to return any PAT in the session, if not found, it tries to fetch it from the mongodb, if not found there either, it creates a new one in gitlab and returns that, as well as saves it in mongo
     */
    function getPersonalAccessToken() {
        $pat = "";
        if(!empty($_SESSION['personalAccessToken'])) {
            return new ApiResponse(200, $_SESSION['personalAccessToken']);
        }
        
        $res = $this->getPersonalAccessTokenFromStorage($_SESSION['gitlabUser']->id);
        if($res !== false && !empty($res)) {
            $pat = $res->pat;
            return new ApiResponse(200, $pat);
        }
        $ar = $this->createPersonalAccessToken();
        return $ar;
    }

    function createPersonalAccessToken($overwriteIfExists = false) {
        global $gitlabAddress, $gitlabAccessToken;
        
        if(!$overwriteIfExists && !empty($_SESSION['personalAccessToken'])) {
            return new ApiResponse(200);
        }

        //$this->deleteAllPersonalAccessTokens(); //Disabled because it's not possible with current Gitlab API

        $this->addLog("Creating new gitlab personal access token");
        $gitlabApiRequest = $gitlabAddress."/api/v4/users/".$_SESSION['gitlabUser']->id."/personal_access_tokens?private_token=".$gitlabAccessToken;
        
        $options = [
            'form_params' => [
                'user_id' => $_SESSION['gitlabUser']->id,
                'name' => "Humlab Speech System Token",
                'scopes[]' => "api"
            ]
        ];
        
        $this->addLog("Creat PAT request: ".$gitlabApiRequest." ".print_r($options, true), "debug");

        $response = $this->httpRequest("POST", $gitlabApiRequest, $options); 

        $this->addLog("Create PAT response: ".print_r($response, true), "debug");
        
        if($response['code'] == 201) { //201 == Created
            $accessTokenResponse = json_decode($response['body']);
            $_SESSION['personalAccessToken'] = $accessTokenResponse->token;
            $this->savePersonalAccessTokenToStorage($_SESSION['gitlabUser']->id, $accessTokenResponse->token);
        }

        $ar = new ApiResponse($response['code'], $_SESSION['personalAccessToken']);
        return $ar;
    }
    
    function getGitlabUser() {
        global $gitlabAddress, $gitlabAccessToken, $gitlabUser;
        //Gets User info from Gitlab for currently logged in user
        $gitlabUsername = $this->getGitLabUsername($_SESSION['email']);
        $gitlabApiRequest = $gitlabAddress."/api/v4/users?username=".$gitlabUsername."&private_token=".$gitlabAccessToken;
    
        $response = $this->httpRequest("GET", $gitlabApiRequest);
    
        $ar = new ApiResponse($response['code']);
    
        if($response['code'] == 200) {
            $userListJson = $response['body'];
            $userList = json_decode($userListJson);
            if(empty($userList)) {
                //User does not exist, so create it and return it
                $arCreateGitlabUser = json_decode($this->createGitlabUser());
                if($arCreateGitlabUser->code == 200) {
                    return $this->getGitlabUser();
                }
                else if($arCreateGitlabUser->code == 409) {
                    return $arCreateGitlabUser;
                }
            }
            else {
                $_SESSION['gitlabUser'] = $userList[0];
                $ar->body = $userList[0];
            }
        }
        else {
            $ar->body = $response['body'];
        }
    
        return $ar;
    }
    
    /**
     * Function: getGitlabUserProjects
     * 
     * Gets Gitlab projects for currently logged in user
     */
    function getGitlabUserProjects() {
        global $gitlabAddress, $hsApiAccessToken;
        
        if(empty($_SESSION['gitlabUser'])) {
            $apiResponse = $this->getGitlabUser();
            $apiResponse = json_decode($apiResponse);
            if($apiResponse['code'] == 409) {
                return $apiResponse;
            }
        }

        if(empty($_SESSION['personalAccessToken'])) {
            $this->createPersonalAccessToken();
        }
        
        $gitlabApiRequest = $gitlabAddress."/api/v4/projects?per_page=9999&owned=false&membership=true&private_token=".$_SESSION['personalAccessToken'];
        
        $response = $this->httpRequest("GET", $gitlabApiRequest);
        $projects = json_decode($response['body']);
        $_SESSION['gitlabProjects'] = $projects;
        
        //Also check if any of these projects have an active running session in the rstudio-router via its API
        $sessions = $this->sessionManagerInterface->_getSessions();
        if($sessions === false) {
            $this->addLog("AppRouter sessions returned false!", "error");
            $sessions = [];
        }
    
        $this->addLog("Sessions array: ".print_r($sessions, true), "debug");

        foreach($projects as $key => $project) {
            $projects[$key]->sessions = array();
            foreach($sessions as $sesKey => $session) {
                if($session->projectId == $project->id) {
                    $projects[$key]->sessions []= $session;
                }
            }
        }
    
        $ar = new ApiResponse($response['code'], $projects);
        
        return $ar;
    }

    function createProject($postData) {
        global $gitlabAddress, $gitlabAccessToken, $appRouterInterface;

        $form = $postData->form;
        $createProjectContextId = $postData->context;

        $response = $this->createGitlabProject($postData);
        if($response['code'] != 201) { //HTTP 201 == CREATED
            $this->addLog("Failed creating Gitlab project", "error");
            return new ApiResponse(500);
        }

        $this->addLog("Create project emuDB trace START:");
        //1. Spawn a new rstudio-container & Git clone project into container (automatic)
        $project = json_decode($response['body']);
        $this->addLog("Project: ".print_r($project, true), "debug");
        array_push($_SESSION['gitlabProjects'], $project);
        
        $uploadsVolume = array(
            'source' => getenv("ABS_ROOT_PATH")."/mounts/edge-router/apache/uploads/".$_SESSION['gitlabUser']->id."/".$createProjectContextId,
            'target' => '/home/uploads'
        );

        $projectDirectoryTemplateVolume = array(
            'source' => getenv("ABS_ROOT_PATH")."/docker/session-manager/project-template-structure",
            'target' => "/project-template-structure"
        );
        
        $volumes = array();
        $volumes []= $uploadsVolume;
        $volumes []= $projectDirectoryTemplateVolume;

        //Make sure uploads volume exists for this user - it might not if this is the first time this user is creating a project and he/she did not upload any files
        $this->createDirectory("/tmp/uploads/".$_SESSION['gitlabUser']->id."/".$createProjectContextId);

        $this->addLog("Launching container to create project");
        $rstudioSessionResponse = $this->sessionManagerInterface->createSession($project->id, "rstudio", $volumes);
        $this->addLog("rstudioSessionResponse: ".print_r($rstudioSessionResponse, true), "debug");
        $rstudioSessionResponseDecoded = json_decode($rstudioSessionResponse->body);
        $rstudioSessionId = $rstudioSessionResponseDecoded->sessionAccessCode;
        $this->addLog("rstudioSessionId: ".$rstudioSessionId, "debug");
        
        $this->addLog("Creating project directory structure");
        //$cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["bash", "-c", "\"cp -R /project-template-structure/* /home/rstudio/\""]);

        $envVars = ["PROJECT_PATH" => "/home/project-setup"];

        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/bin/bash", "/scripts/copy-template-directory-structure.sh"], $envVars);

        //2. Generate a new empty emu-db in container git dir
        $this->addLog("Creating emuDB in project");
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/local/bin/R", "-f", "/scripts/createEmuDb.r"], $envVars);
        $this->addLog($cmdOutput);

        //Just about here we want to include any uploaded files
        $this->addLog("Importing wav files into project");
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/local/bin/R", "-f", "/scripts/importWavFiles.r"], $envVars);

        //Create a generic bundle-list for all bundles
        $this->addLog("Creating bundle lists");
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/local/bin/R", "-f", "/scripts/createBundleList.r"], $envVars);
        
        //$this->addLog("postData: ".print_r($postData, true), "desbug");

        $this->addLog("Creating and linking annotation levels");
        $this->createAnnotLevelsInSession($rstudioSessionId, $form);
        
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/bin/bash", "-c", "cp -R ".$envVars["PROJECT_PATH"]."/* /home/rstudio/humlabspeech/"]);

        //3. Commit & push
        $this->addLog("Committing project");
        $cmdOutput = $this->sessionManagerInterface->commitSession($rstudioSessionId);
        //addLog("commit-cmd-output: ".print_r($cmdOutput, true), "debug");
        //4. Shutdown container
        
        $this->addLog("Shutting down project creation container");
        $cmdOutput = $this->sessionManagerInterface->delSession($rstudioSessionId);
        
        //addLog("session-del-cmd-output: ".print_r($cmdOutput, true), "debug");

        return new ApiResponse(200);
    }
    
    function createGitlabProject($postData) {
        global $gitlabAddress, $gitlabAccessToken, $appRouterInterface;
        
        $form = $postData->form;
        $createProjectContextId = $postData->context;

        $gitlabApiRequest = $gitlabAddress."/api/v4/projects/user/".$_SESSION['gitlabUser']->id."?private_token=".$gitlabAccessToken;
        
        $this->addLog("Creating new GitLab project:".print_r($postData, true));

        $response = $this->httpRequest("POST", $gitlabApiRequest, [
            'form_params' => [
                'name' => $form->projectName
            ]
        ]);
    
        $this->addLog("Gitlab project create response: ".print_r($response, true), "debug");

        return $response;
    }

    /**
     * Function: createAnnotLevels
     * 
     * Create annotation levels in emuDB
     */
    function createAnnotLevelsInSession($rstudioSessionId, $form, $env = []) {
        //Create annoation levels
        foreach($form->annotLevels as $annotLevel) {
            $cmd = ["/usr/local/bin/R", "-f", "/scripts/addAnnotationLevelDefinition.r"];
            $env["ANNOT_LEVEL_DEF_NAME"] = $annotLevel->name;
            $env["ANNOT_LEVEL_DEF_TYPE"] = $annotLevel->type;

            $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, $cmd, $env);
        }

        //Create the links between annotation levels
        foreach($form->annotLevelLinks as $annotLevelLink) {
            $cmd = ["/usr/local/bin/R", "-f", "/scripts/addAnnotationLevelLinkDefinition.r"];
            $env["ANNOT_LEVEL_LINK_SUPER"] = $annotLevelLink->superLevel;
            $env["ANNOT_LEVEL_LINK_SUB"] = $annotLevelLink->subLevel;
            $env["ANNOT_LEVEL_LINK_DEF_TYPE"] = $annotLevelLink->type;

            $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, $cmd, $env);
        }
    }
    
    function deleteGitlabProject($projectId) {
        global $gitlabAddress, $gitlabAccessToken;
    
        $gitlabUsername = $this->getGitLabUsername($_SESSION['email']);
        $gitlabApiRequest = $gitlabAddress."/api/v4/projects/".$projectId."?private_token=".$gitlabAccessToken;
        
        $response = $this->httpRequest("DELETE", $gitlabApiRequest);
    
        $ar = new ApiResponse($response['code'], $response['body']);
        return $ar;
    }


    /**
     * Function: sanitize
     * 
     * Blatantly stolen from https://stackoverflow.com/questions/2668854/sanitizing-strings-to-make-them-url-and-filename-safe?lq=1
     */
    function sanitize($string, $force_lowercase = false, $anal = false) {
        $strip = array("~", "`", "!", "@", "#", "$", "%", "^", "&", "*", "=", "+", "[", "{", "]",
                       "}", "\\", "|", ";", ":", "\"", "'", "&#8216;", "&#8217;", "&#8220;", "&#8221;", "&#8211;", "&#8212;",
                       "â€”", "â€“", ",", "<", ">", "/", "?");
        $clean = trim(str_replace($strip, "", strip_tags($string)));
        $clean = preg_replace('/\s+/', "-", $clean);
        $clean = ($anal) ? preg_replace("/[^a-zA-Z0-9]/", "", $clean) : $clean ;
        return ($force_lowercase) ?
            (function_exists('mb_strtolower')) ?
                mb_strtolower($clean, 'UTF-8') :
                strtolower($clean) :
            $clean;
    }
}

$app = new Application();
$routerOutput = $app->route();
echo $routerOutput;


?>
