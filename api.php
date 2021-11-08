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
$gitlabRootAccessToken = getenv("GIT_API_ACCESS_TOKEN");
$hsApiAccessToken = getenv("HS_API_ACCESS_TOKEN");

class Application {
    function __construct() {
        global $hsApiAccessToken;
        $this->sessionManagerInterface = new SessionManagerInterface($this, $hsApiAccessToken);
    }

    /**
     * Function: restMatchPath
     * 
     * Takes a request path and a REST path template and figures out if they match and extracts vars defined with :myvar
     * 
     */
    function restMatchPath($path, $template) {
        $regexp = $template;
        $varMatches = null;
        preg_match_all("/:[a-z0-9_]*/", $regexp, $varMatches);

        if(count($varMatches) > 0) {
            $varMatches = $varMatches[0];
            foreach($varMatches as $key => $vm) {
                $varMatches[$key] = str_replace(":", "", $varMatches[$key]);
            }
        }

        $regexp = "/".str_replace("/", "\/", $regexp)."/";
        $regexp = preg_replace("/(:[a-z0-9_]*)/", "([a-z0-9_]*)", $regexp);
        $matches = null;
        $match = preg_match($regexp, $path, $matches);
        if($match) {
            $varMap = [];
            foreach($varMatches as $key => $vm) {
                $varMap[$vm] = $matches[$key+1];
            }

            return ['matched' => true, 'varMap' => $varMap];
        }
        return ['matched' => false];
    }

    function route() {
        $apiResponse = false;
        $reqPath = $_SERVER['REQUEST_URI'];

        //Strip multiple leading /
        while(strpos($reqPath, "/") === 0) {
            $reqPath = substr($reqPath, 1);
        }
        $reqPath = "/".$reqPath;
        
        //Special case for letting the session-manager validate & retrieve a PHP session
        if(isset($_GET['f']) && $_GET['f'] == "session") {
            $this->addLog("Session validation for ".$_COOKIE['PHPSESSID']." - ".session_id(), "debug");            
            //This might seem strange since there's no apparent authentication, but the authentication is implicit since the session-manager
            //must pass the correct PHPSESSID via a cookie header in order for the $_SESSION to be filled with the correct values
            //otherwise a new empty session will be returned

            $apiResponse = new ApiResponse(200, json_encode($_SESSION));
            return $apiResponse->toJSON();
        }

        $reqMethod = $_SERVER['REQUEST_METHOD'];

        //PUBLIC METHODS
        if($reqMethod == "GET") {
            switch($reqPath) {
                case "/api/v1/isgitlabready":
                    $this->addLog("GET: /api/v1/isgitlabready", "debug");
                    $sessManApiResponse = $this->sessionManagerInterface->isGitlabReady();
                    $ar = new ApiResponse($sessManApiResponse['code'], $sessManApiResponse['body']);
                    return $ar->toJSON(false);
                break;
            }
        }

        //AUTH CONTROL - ALL METHODS BEYOND THIS POINT REQUIRES THE USER TO BE SIGNED-IN
        if(empty($_SESSION['authorized']) || $_SESSION['authorized'] !== true) {
            //if user has not passed a valid authentication, don't allow access to this API
            $this->addLog("User not signed in - Authorization required");
            $ar = new ApiResponse(401, "Authorization required");
            echo $ar->toJSON();
            exit();
        }

        if($reqMethod == "GET") {
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/personalaccesstoken");
            if($matchResult['matched']) {
                $apiResponse = $this->getPersonalAccessToken();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/user");
            if($matchResult['matched']) {
                $apiResponse = $this->getGitlabUser();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/session");
            if($matchResult['matched']) {
                $apiResponse = $this->getUserSessionAttributes();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/user/project");
            if($matchResult['matched']) {
                $apiResponse = $this->getGitlabUserProjects();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/signout");
            if($matchResult['matched']) {
                $apiResponse = $this->signOut();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/user/project/:project_id/session");
            if($matchResult['matched']) {
                $apiResponse = $this->getProjectOperationsSession($matchResult['varMap']['project_id']);
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/availibility/project/:project_id/session/:session_name");
            if($matchResult['matched']) {
                $apiResponse = $this->checkAvailabilityOfEmuSessionName($matchResult['varMap']['project_id'], $matchResult['varMap']['session_name']);
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

            $matchResult = $this->restMatchPath($reqPath, "/api/v1/upload");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/upload", "debug");
                $apiResponse = $this->handleUpload();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/personalaccesstoken");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/personalaccesstoken", "debug");
                $apiResponse = $this->createPersonalAccessToken();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/user");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/user", "debug");
                $apiResponse = $this->createGitlabUser();
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/user/project");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/user/project", "debug");
                //TODO: Perhaps verify that this user has the right to create a new project?
                $apiResponse = $this->createProject($postData);
            }
            
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/user/project/add");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/user/project/add", "debug");
                //TODO: Perhaps verify that this user has the right to create a new project?
                $apiResponse = $this->addSessionsToProject($postData);
            }

            $matchResult = $this->restMatchPath($reqPath, "/api/v1/rstudio/session/please");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/rstudio/session/please", "debug");
                if($this->userHasProjectAuthorization($postData->projectId)) {
                    $apiResponse = $this->sessionManagerInterface->fetchSession($postData->projectId, "rstudio");
                }
                else {
                    $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                }
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/jupyter/session/please");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/jupyter/session/please", "debug");
                if($this->userHasProjectAuthorization($postData->projectId)) {
                    $apiResponse = $this->sessionManagerInterface->fetchSession($postData->projectId, "jupyter");
                }
                else {
                    $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                }
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/vscode/session/please");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/vscode/session/please", "debug");
                if($this->userHasProjectAuthorization($postData->projectId)) {
                    $apiResponse = $this->sessionManagerInterface->fetchSession($postData->projectId, "vscode");
                }
                else {
                    $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                }
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/emu-webapp/session/please");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/emu-webapp/session/please", "debug");
                if($this->userHasProjectAuthorization($postData->projectId)) {
                    $apiResponse = new ApiResponse(200, array('personalAccessToken' => $_SESSION['personalAccessToken']));
                }
                else {
                    $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                }
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/session/save");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/session/save", "debug");
                if($this->userHasProjectAuthorization($postData->projectId)) {
                    $apiResponse = $this->sessionManagerInterface->commitSession($postData->sessionId);
                }
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/session/close");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/session/close", "debug");
                if($this->userHasProjectAuthorization($postData->projectId)) {
                    $apiResponse = $this->sessionManagerInterface->delSession($postData->sessionId);
                }
            }
            $matchResult = $this->restMatchPath($reqPath, "/api/v1/user/project/delete");
            if($matchResult['matched']) {
                $this->addLog("POST: /api/v1/user/project/delete", "debug");
                if($this->userHasProjectAuthorization($postData->projectId)) {
                    $apiResponse = $this->deleteGitlabProject($postData->projectId);
                }
                else {
                    $apiResponse = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                }
            }
            return $apiResponse->toJSON();
        }
    }

    /**
     * Function: checkAvailabilityOfSessionName
     * Check if this project name is available (not already taken) in the project
     */
    function checkAvailabilityOfEmuSessionName($projectId, $emuSessionName) {
        $session = $this->sessionManagerInterface->getSessionFromRegistryByProjectId($projectId);
        if($session === false) {
            $ar = new ApiResponse(200, "No live session");
            return $ar;
        }
        /*
        $emuDbScanResult = $this->sessionManagerInterface->runCommandInSession(["/usr/bin/node", "/container-agent/main.js", "emudb-scan"]);
        $this->addLog(print_r($emuDbScanResult, true), "debug");
        $ar = new ApiResponse(200, print_r($emuDbScanResult, true));
        */
        $ar = new ApiResponse(200, "Not doing that");
        return $ar;
    }

    function getProjectOperationsSession($projectId) {
        $this->addLog("getProjectOperationsSession ".$projectId, "debug");

        $sessionResponse = $this->sessionManagerInterface->createSession($projectId, "operations");
        $sessionResponseDecoded = json_decode($sessionResponse->body);
        $sessionId = $sessionResponseDecoded->sessionAccessCode;

        $this->addLog("Created operations session ".$sessionId);

        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "emudb-scan"], $envVars);
        $this->addLog($cmdOutput, "debug");

        $this->sessionManagerInterface->getEmuDbProperties();

        $ar = new ApiResponse(200);
        return $ar;
    }

    function getMongoDb() {
        $mongoPass = getenv("MONGO_ROOT_PASSWORD");
        $client = new Client("mongodb://root:".$mongoPass."@mongo");
        $database = $client->selectDatabase('humlab_speech');
        return $database;
    }

    function getMongoPatCollection() {
        $database = $this->getMongoDb();
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
        $this->addLog("Http Request: ".$method." ".$url, "debug");
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
        global $gitlabAddress, $gitlabRootAccessToken;
    
        $arProjects = $this->getGitlabUserProjects();
        $projects = $arProjects->body;
    
        $foundProject = false;
        foreach($projects as $key => $project) {
            if($project->id == $projectId) {
                $foundProject = true;
            }
        }
        if(!$foundProject) {
            $this->addLog("User attempted to access unauthorized project.", "warn");
            $this->addLog(print_r($_SESSION['gitlabUser'], true), "debug");
        }
        return $foundProject;
    }
    
    function handleUpload() {
        $this->addLog("handleUpload", "debug");
        $data = json_decode($_POST['data']);
        $this->addLog("Received upload request of file with filename '".$data->filename."'");
        $fileData = $data->file;
        $fileName = $this->sanitize($data->filename);
        //The 'group' is an arbitrary name which creates a grouping of files. For example the Documentation upload form component would define its own group for the files/docs uploaded through it, so that they can stay bundled in their own subdir
        $group = $this->sanitize($data->group);

        $this->addLog("Post-sanitization filename: ".$fileName, "debug");
        $this->addLog("Post-sanitization group name: ".$group, "debug");

        //file data looks like: data:audio/wav;base64,UklGRoQuFgBXQVZFZm10IBAAAAABAAEAgLsAAAB3AQACABAA
        $pos = strpos($fileData, ";base64,");
        $mime = substr($fileData, 5, $pos);
        $this->addLog("Reported mime-type of file is: ".$mime, "debug");
        $fileDataWithoutMime = substr($fileData, $pos+8);

        $fileDataWithoutMime = str_replace(' ','+',$fileDataWithoutMime);
        $fileBinary = base64_decode($fileDataWithoutMime, true);
        $this->addLog("File size of ".$fileName." is ".strlen($fileBinary)." bytes", "debug");

        $targetDir = "/tmp/uploads/".$_SESSION['gitlabUser']->id."/".$data->context."/".$group;

        $this->addLog("File destination: ".$targetDir, "debug");
        
        $this->createDirectory($targetDir);

        file_put_contents($targetDir."/".$fileName, $fileBinary);

        $ar = new ApiResponse(200);
        return $ar;
    }

    function createDirectory($targetDir) {
        if(!is_dir($targetDir)) {
            $oldUmask = umask(0);
            $mkdirResult = mkdir($targetDir, 0700, true);
            umask($oldUmask);
            if(!$mkdirResult) {
                $processUser = posix_getpwuid(posix_geteuid());
                $this->addLog("Failed creating upload destination! : ".$targetDir." As user: ".$processUser['name'], "error");
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
        return $_SESSION['username'];
        //return str_replace("@", "_at_", $email);
    }
    
    function addLog($msg, $level = "info") {
        $level = strtolower($level);

        if(is_object($msg)) {
            $msg = serialize($msg);
        }

        if($level == "info" || $level == "error") {
            file_put_contents("/var/log/api/webapi.log", date("Y-m-d H:i:s")." [".strtoupper($level)."] ".$msg."\n", FILE_APPEND);
            file_put_contents("/var/log/api/webapi.debug.log", date("Y-m-d H:i:s")." [".strtoupper($level)."] ".$msg."\n", FILE_APPEND);
        }
        if($level == "debug") {
            file_put_contents("/var/log/api/webapi.debug.log", date("Y-m-d H:i:s")." [".strtoupper($level)."] ".$msg."\n", FILE_APPEND);
        }
    }
    
    function getUserSessionAttributes() {

        if(empty($_SESSION['gitlabUser'])) {
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
            'username' => $this->getGitLabUsername($_SESSION['email']),
            'id' => $_SESSION['gitlabUser']->id,
            'personalAccessToken' => $_SESSION['personalAccessToken']
        ];
    
        return new ApiResponse(200, $output);
    }
    
    function createGitlabUser() {
        global $gitlabAddress, $gitlabRootAccessToken;

        $gitlabUsername = $this->getGitLabUsername($_SESSION['email']);
        $this->addLog("Creating GitLab user ".$gitlabUsername);
        $gitlabApiRequest = $gitlabAddress."/api/v4/users?username=".$gitlabUsername."&private_token=".$gitlabRootAccessToken;
    
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
        $this->addLog("deleteAllPersonalAccessTokens", "debug");
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
        global $gitlabAddress, $gitlabRootAccessToken;
        $gitlabApiRequest = $gitlabAddress."/api/v4/personal_access_tokens/".$tokenId."?private_token=".$gitlabRootAccessToken;
        $response = $this->httpRequest("DELETE", $gitlabApiRequest);
        return new ApiResponse($response['code'], $response['body']);
    }

    function fetchPersonalAccessTokens() {
        global $gitlabAddress, $gitlabRootAccessToken;
        $gitlabApiRequest = $gitlabAddress."/api/v4/personal_access_tokens?user_id=".$_SESSION['gitlabUser']->id."&private_token=".$gitlabRootAccessToken;
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
        global $gitlabAddress, $gitlabRootAccessToken;
        
        if(!$overwriteIfExists && !empty($_SESSION['personalAccessToken'])) {
            return new ApiResponse(200);
        }

        //$this->deleteAllPersonalAccessTokens(); //Disabled because it's not possible with current Gitlab API

        $this->addLog("Creating new gitlab personal access token");
        $gitlabApiRequest = $gitlabAddress."/api/v4/users/".$_SESSION['gitlabUser']->id."/personal_access_tokens?private_token=".$gitlabRootAccessToken;
        
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
        global $gitlabAddress, $gitlabRootAccessToken, $gitlabUser;
        //Gets User info from Gitlab for currently logged in user
        $gitlabUsername = $this->getGitLabUsername($_SESSION['email']);
        $gitlabApiRequest = $gitlabAddress."/api/v4/users?username=".$gitlabUsername."&private_token=".$gitlabRootAccessToken;
    
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
                $_SESSION['id'] = $_SESSION['gitlabUser']->id;
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

    function addSessionsToProject($postData) {
        global $gitlabAddress, $gitlabRootAccessToken, $appRouterInterface;
        $form = $postData->form;
        $formContextId = $postData->context;
        
        $uploadsVolume = array(
            'source' => getenv("ABS_ROOT_PATH")."/mounts/edge-router/apache/uploads/".$_SESSION['gitlabUser']->id."/".$formContextId,
            'target' => '/home/uploads'
        );

        $volumes = array();
        $volumes []= $uploadsVolume;

        $this->createDirectory("/tmp/uploads/".$_SESSION['gitlabUser']->id."/".$formContextId);

        $sessionResponse = $this->sessionManagerInterface->createSession($postData->projectId, "operations", $volumes);
        $sessionResponseDecoded = json_decode($sessionResponse->body);
        $sessionId = $sessionResponseDecoded->sessionAccessCode;

        $envVars = array();
        $envVars["PROJECT_PATH"] = "/home/rstudio/project";
        $envVars['EMUDB_SESSIONS'] = base64_encode(json_encode($form->sessions));
        $envVars['UPLOAD_PATH'] = "/home/uploads";

        //Check here that any of the requested session names does not already exist!
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "emudb-scan"], $envVars);
        $this->addLog("emudb-scan output: ".print_r($cmdOutput, true), "debug");
        
        $apiResponse = $cmdOutput;
        $emuDb = json_decode($apiResponse->body);

        foreach($emuDb->sessions as $session) {
            foreach($form->sessions as $formSession) {
                if($session->name == $formSession->name) {
                    $this->addLog("Early shutdown of project container due to session name conflict");
                    $cmdOutput = $this->sessionManagerInterface->delSession($sessionId);
                    return new ApiResponse(400, "The session name '".$formSession->name."' already exists in the EmuDB.");
                }
            }
        }

        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "emudb-create-sessions"], $envVars);
        $this->addLog("emudb-create-sessions output: ".print_r($cmdOutput, true), "debug");

        $this->addLog("Creating bundle lists");
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "emudb-create-bundlelist"], $envVars);

        //3. Commit & push
        $this->addLog("Committing project");
        $cmdOutput = $this->sessionManagerInterface->commitSession($sessionId);
        
        $this->addLog("Shutting down project creation container");
        $cmdOutput = $this->sessionManagerInterface->delSession($sessionId);

        return new ApiResponse(200, "Added sessions to project");
    }

    function createProject($postData) {
        global $gitlabAddress, $gitlabRootAccessToken, $appRouterInterface;

        $form = $postData->form;
        $formContextId = $postData->context;

        foreach($form->sessions as $key => $session) {
            $form->sessions[$key]->name = $this->sanitize($session->name);
        }

        $response = $this->createGitlabProject($postData);
        if($response['code'] != 201) { //HTTP 201 == CREATED
            $this->addLog("Failed creating Gitlab project", "error");
            return new ApiResponse(500);
        }

        $project = json_decode($response['body']);
        array_push($_SESSION['gitlabProjects'], $project);
        
        $uploadsVolume = array(
            'source' => getenv("ABS_ROOT_PATH")."/mounts/edge-router/apache/uploads/".$_SESSION['gitlabUser']->id."/".$formContextId,
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
        //Note that this will create a dir inside the edge-router container, since that's where this is being executed
        $this->createDirectory("/tmp/uploads/".$_SESSION['gitlabUser']->id."/".$formContextId);

        $this->addLog("Launching project create container");
        $sessionResponse = $this->sessionManagerInterface->createSession($project->id, "operations", $volumes);
        $sessionResponseDecoded = json_decode($sessionResponse->body);
        $sessionId = $sessionResponseDecoded->sessionAccessCode;

        $envVars = array();
        $envVars["PROJECT_PATH"] = "/home/project-setup";
        $envVars['EMUDB_SESSIONS'] = base64_encode(json_encode($form->sessions));
        $envVars['UPLOAD_PATH'] = "/home/uploads";

        if($form->standardDirectoryStructure) {
            $this->createStandardDirectoryStructure($sessionId, $envVars);
            if($form->createEmuDb) {
                $this->createEmuDb($sessionId, $envVars, $form);
            }
        }

        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "full-recursive-copy", $envVars["PROJECT_PATH"], "/home/rstudio/project"], $envVars);
        $this->addLog("copy-dir-output: ".print_r($cmdOutput, true), "debug");        

        //3. Commit & push
        $this->addLog("Committing project");
        $cmdOutput = $this->sessionManagerInterface->commitSession($sessionId);
        
        $this->addLog("Shutting down project creation container");
        $cmdOutput = $this->sessionManagerInterface->delSession($sessionId);

        return new ApiResponse(200);
    }

    function createStandardDirectoryStructure($sessionId, $envVars) {
        $this->addLog("Creating project directory structure");
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "copy-project-template-directory"], $envVars);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Created project directory structure");
        }


        //And copy any uploaded docs
        $cmdOutput = $this->sessionManagerInterface->copyUploadedFiles($sessionId);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Copied uploaded files");
        }
    }

    function createEmuDb($sessionId, $envVars, $form) {
        $this->addLog("Creating emuDB in project");

        //Generate a new empty emu-db in container git dir
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "emudb-create"], $envVars);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Created EmuDB");
        }
        
        $this->addLog("Creating EmuDB sessions in project");
        /*
        $this->addLog("Would run:");
        $this->addLog(print_r(["/usr/bin/node", "/container-agent/main.js", "emudb-create-sessions"], true));
        $this->addLog(print_r($envVars, true));
        */
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "emudb-create-sessions"], $envVars);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Created sessions in EmuDB");
        }
        
        //Create a generic bundle-list for all bundles
        $this->addLog("Creating bundle lists");
        /*
        $this->addLog("Would run:");
        $this->addLog(print_r(["/usr/bin/node", "/container-agent/main.js", "emudb-create-bundlelist"], true));
        $this->addLog(print_r($envVars, true));
        */
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, ["/usr/bin/node", "/container-agent/main.js", "emudb-create-bundlelist"], $envVars);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Created bundlelists in EmuDB");
        }

        $this->createAnnotLevelsInSession($sessionId, $form, $envVars);
    }
    
    function createGitlabProject($postData) {
        global $gitlabAddress, $gitlabRootAccessToken, $appRouterInterface;
        
        $form = $postData->form;
        $createProjectContextId = $postData->context;

        $gitlabApiRequest = $gitlabAddress."/api/v4/projects/user/".$_SESSION['gitlabUser']->id."?private_token=".$gitlabRootAccessToken;
        
        $this->addLog("Creating new GitLab project:".print_r($postData, true), "debug");

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
    function createAnnotLevelsInSession($sessionId, $form, $env = []) {
        $this->addLog("Creating and linking annotation levels");
        //Create annoation levels
        foreach($form->annotLevels as $annotLevel) {
            $cmd = ["/usr/bin/node", "/container-agent/main.js", "emudb-create-annotlevels"];
            $env["ANNOT_LEVEL_DEF_NAME"] = $annotLevel->name;
            $env["ANNOT_LEVEL_DEF_TYPE"] = $annotLevel->type;

            $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, $cmd, $env);
            $response = $this->handleContainerAgentResponse($cmdOutput);
            if($response->code == 200) {
                $this->addLog("Created annotation levels in EmuDB");
            }
        }

        //Create the links between annotation levels
        foreach($form->annotLevelLinks as $annotLevelLink) {
            $cmd = ["/usr/bin/node", "/container-agent/main.js", "emudb-create-annotlevellinks"];
            $env["ANNOT_LEVEL_LINK_SUPER"] = $annotLevelLink->superLevel;
            $env["ANNOT_LEVEL_LINK_SUB"] = $annotLevelLink->subLevel;
            $env["ANNOT_LEVEL_LINK_DEF_TYPE"] = $annotLevelLink->type;

            $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, $cmd, $env);
            $response = $this->handleContainerAgentResponse($cmdOutput);
            if($response->code == 200) {
                $this->addLog("Created annotation level links in EmuDB");
            }
        }

        //Set level canvases order
        $env["ANNOT_LEVELS"] = base64_encode(json_encode($form->annotLevels));
        $cmd = ["/usr/bin/node", "/container-agent/main.js", "emudb-setlevelcanvasesorder"];
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, $cmd, $env);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Set level canvases order in EmuDB");
        }

        //Add perspectives
        $cmd = ["/usr/bin/node", "/container-agent/main.js", "emudb-add-default-perspectives"];
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, $cmd, $env);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Add default perspectives in EmuDB");
        }

        //Add ssff tracks
        $cmd = ["/usr/bin/node", "/container-agent/main.js", "emudb-ssff-track-definitions"];
        $cmdOutput = $this->sessionManagerInterface->runCommandInSession($sessionId, $cmd, $env);
        $response = $this->handleContainerAgentResponse($cmdOutput);
        if($response->code == 200) {
            $this->addLog("Add ssff tracks in EmuDB");
        }
    }
    
    function deleteGitlabProject($projectId) {
        global $gitlabAddress, $gitlabRootAccessToken;
    
        $gitlabUsername = $this->getGitLabUsername($_SESSION['email']);
        $gitlabApiRequest = $gitlabAddress."/api/v4/projects/".$projectId."?private_token=".$gitlabRootAccessToken;
        
        $response = $this->httpRequest("DELETE", $gitlabApiRequest);
    
        $ar = new ApiResponse($response['code'], $response['body']);
        return $ar;
    }

    function handleContainerAgentResponse($response) {
        if(is_string($response)) {
            $response = @json_decode($response);
            if(!is_object($response)) {
                $this->addLog("Could not parse Container-agent response", "error");
                return false;
            }
        }
        if($response->code != 200) {
            $this->addLog($responseJson, "error");
        }

        return $response;
    }

    /**
     * Function: sanitize
     * 
     * Blatantly stolen from https://stackoverflow.com/questions/2668854/sanitizing-strings-to-make-them-url-and-filename-safe?lq=1
     */
    function sanitize($string, $force_lowercase = false, $anal = false) {
        $strip = array("~", "`", "!", "@", "#", "$", "%", "^", "&", "*", "=", "+", "[", "{", "]",
                       "}", "\\", "|", ";", ":", "\"", "'", "&#8216;", "&#8217;", "&#8220;", "&#8221;", "&#8211;", "&#8212;",
                       "â€”", "â€“", ",", "<", ">", "?", "(", ")");
        $clean = trim(str_replace($strip, "", strip_tags($string)));
        $clean = preg_replace('/\s+/', "_", $clean);
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
