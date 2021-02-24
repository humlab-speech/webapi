<?php
require 'vendor/autoload.php';
require 'SessionManagerInterface.class.php';
require_once 'ApiResponse.class.php';

use GuzzleHttp\Psr7;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ClientException;

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
            $ar= new ApiResponse(401, "Authorization required");
            echo $ar->toJSON();
            exit();
        }

        $reqPath = $_SERVER['REQUEST_URI'];
        $reqMethod = $_SERVER['REQUEST_METHOD'];
        
        if($reqMethod == "GET") {
            switch($reqPath) {
                case "/api/v1/magick":
                    $this->addLog("GET: /api/v1/magick");
                    $out = $this->dumpServerVariables();
                break;
                case "/api/v1/user":
                    $this->addLog("GET: /api/v1/user");
                    $out = $this->getGitlabUser();
                break;
                case "/api/v1/session":
                    $this->addLog("GET: /api/v1/session");
                    $out = $this->getUserSessionAttributes();
                break;
                case "/api/v1/user/project":
                    $this->addLog("GET: /api/v1/user/project");
                    $out = $this->getGitlabUserProjects();
                break;
                case "/api/v1/signout":
                    $this->addLog("GET: /api/v1/signout");
                    $this->signOut();
                break;
            }
            return $out;
        }
        
        if($reqMethod == "POST") {
            $postData = [];
            if(!empty($_POST['data'])) {
                $postData = json_decode($_POST['data']);
            }
        
            switch($reqPath) {
                case "/api/v1/upload":
                    $this->addLog("POST: /api/v1/upload");
                    $ar = $this->handleUpload();
                    $out = $ar->toJSON();
                break;
                case "/api/v1/personalaccesstoken":
                    $this->addLog("POST: /api/v1/personalaccesstoken");
                        $out = $this->createPersonalAccessToken();
                break;
                case "/api/v1/user":
                    $this->addLog("POST: /api/v1/user");
                    $out = $this->createGitlabUser();
                break;
                case "/api/v1/user/project":
                    $this->addLog("POST: /api/v1/user/project");
                    //TODO: Perhaps verify that this user has the right to create a new project?
                    $out = $this->createGitlabProject();
                break;
                case "/api/v1/rstudio/session/please":
                    $this->addLog("POST: /api/v1/rstudio/session/please");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $ar = $this->sessionManagerInterface->fetchSession($postData->projectId, "rstudio");
                        $out = $ar->toJSON();
                    }
                    else {
                        $ar = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                        $out = $ar->toJSON();
                    }
                break;
                case "/api/v1/emuwebapp/session/please":
                    $this->addLog("POST: /api/v1/emuwebapp/session/please");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $ar = new ApiResponse(200, array('personalAccessToken' => $_SESSION['personalAccessToken']));
                        $out = $ar->toJSON();
                    }
                    else {
                        $ar = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                        $out = $ar->toJSON();
                    }
                break;
                case "/api/v1/rstudio/save":
                    $this->addLog("POST: /api/v1/rstudio/save");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $out = $this->sessionManagerInterface->commitSession($postData->rstudioSession);
                    }
                break;
                case "/api/v1/rstudio/close":
                    $this->addLog("POST: /api/v1/rstudio/close");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $out = $this->sessionManagerInterface->delSession($postData->rstudioSession);
                    }
                break;
                case "/api/v1/user/project/delete":
                    $this->addLog("POST: /api/v1/user/project/delete");
                    if($this->userHasProjectAuthorization($postData->projectId)) {
                        $out = $this->deleteGitlabProject($postData->projectId);
                    }
                    else {
                        $ar = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                        $out = $ar->toJSON();
                    }
                break;
            }
            return $out;
        }
    }

    function httpRequest($method = "GET", $url, $options = []) {
        $this->addLog("Http Request: ".$method." ".$url);
        $this->addLog(print_r($options, true), "debug");
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
    
        /*
        if(strtolower($method) == "post" || strtolower($method) == "put") {
            try {
                $response = $httpClient->request($method, $url, $options);
            }
            catch(Exception $e) {
                $exception = $e;
            }
        }
    
        if(strtolower($method) == "get" || strtolower($method) == "delete" ) {
            try {
                $response = $httpClient->request($method, $url);
            }
            catch(Exception $e) {
                $exception = $e;
            }
        }
        */
    
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
        if(!is_dir($targetDir)) {
            mkdir($targetDir, 0777, true);
        }
        file_put_contents($targetDir."/".$fileName, $fileBinary);

        $ar = new ApiResponse(200);
        return $ar;
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
    }
    
    
    /**
     * For debugging
     */
    function dumpServerVariables() {
        echo "SERVER:\n";
        print_r($_SERVER);
        echo "SESSION:\n";
        print_r($_SESSION);
        echo "\n";
        echo $this->getGitLabUsername($_SESSION['email']);
    }
    /*
    if($reqMethod == "DELETE") {
        switch($reqPath) {
        }
    }
    */
    
    function getGitLabUsername($email) {
        return str_replace("@", "_at_", $email);
    }
    
    function addLog($msg, $level = "info") {
        global $logLevel;
        if($level == "debug" && $logLevel != "debug") {
            return;
        }
        file_put_contents("/var/log/api/webapi.log", date("Y-m-d H:i:s")." [".strtoupper($level)."] ".$msg."\n", FILE_APPEND);
    }
    
    function getUserSessionAttributes() {
        //If we don't have a PAT yet, fetch it now
        if(empty($_SESSION['personalAccessToken'])) {
            $response = $this->createPersonalAccessToken();
            if($response['code'] == 200) {
                $_SESSION['personalAccessToken'] = $response['body'];
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
    
        $ar = new ApiResponse(200, $output);
        return $ar->toJSON();
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
    
        return $ar->toJSON();
    }

    function deleteAllPersonalAccessTokens($onlySystemTokens = true) {
        $ar = $this->fetchPersonalAccessTokens();
        $tokenList = json_decode($ar->body);
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

    function createPersonalAccessToken($overwriteIfExists = false) {
        global $gitlabAddress, $gitlabAccessToken;
        
        if(!$overwriteIfExists && !empty($_SESSION['personalAccessToken'])) {
            $ar = new ApiResponse(200);
            return $ar->toJSON();
        }

        $this->deleteAllPersonalAccessTokens();

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
        }

        $ar = new ApiResponse($response['code']);
        return $ar->toJSON();
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
                $arCreateGitlabUser = $this->createGitlabUser();
                if(json_decode($arCreateGitlabUser)->code == 200) {
                    return $this->getGitlabUser();
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
    
        return $ar->toJSON();
    }
    
    /**
     * Function: getGitlabUserProjects
     * 
     * Gets Gitlab projects for currently logged in user
     */
    function getGitlabUserProjects() {
        global $gitlabAddress, $hsApiAccessToken;
        
    
        if(empty($_SESSION['gitlabUser'])) {
            $this->getGitlabUser();
        }

        if(empty($_SESSION['personalAccessToken'])) {
            $this->createPersonalAccessToken();
        }
        
        $gitlabApiRequest = $gitlabAddress."/api/v4/projects?per_page=9999&owned=false&membership=true&private_token=".$_SESSION['personalAccessToken'];
        
        $response = $this->httpRequest("GET", $gitlabApiRequest);
        $projects = json_decode($response['body']);
        $_SESSION['gitlabProjects'] = $projects;
        
        //Also check if any of these projects have an active running session in the rstudio-router via its API
        $sessions = $this->sessionManagerInterface->getSessions();
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
        
        return $ar->toJSON();
    }
    
    function createGitlabProject() {
        global $gitlabAddress, $gitlabAccessToken, $appRouterInterface;
        
        $gitlabApiRequest = $gitlabAddress."/api/v4/projects/user/".$_SESSION['gitlabUser']->id."?private_token=".$gitlabAccessToken;
        
        $postData = json_decode($_POST['data']);
    
        $this->addLog("Creating new GitLab project:".print_r($postData, true));

        $response = $this->httpRequest("POST", $gitlabApiRequest, [
            'form_params' => $postData
        ]);
    
        $this->addLog("Gitlab project create response: ".print_r($response, true), "debug");
    
        if($response['code'] == 201) { //HTTP 201 == CREATED
            if($postData->genEmuDb) {
                $this->addLog("Create project emuDB trace START:");
                //1. Spawn a new rstudio-container & Git clone project into container (automatic)
                $project = json_decode($response['body']);
                //addLog("Project: ".print_r($project, true), "debug");
                
                $this->addLog("Session projects num: ".count($_SESSION['gitlabProjects']), "debug");
    
                array_push($_SESSION['gitlabProjects'], $project);
                
                $this->addLog("Session projects num: ".count($_SESSION['gitlabProjects']), "debug");
    
                $uploadsVolume = array(
                    //'source' => "/tmp/uploads/".$_SESSION['gitlabUser']->id."/".$postData->context,
                    'source' => "/home/johan/humlab-speech-deployment/mounts/edge-router/apache/uploads/".$_SESSION['gitlabUser']->id."/".$postData->context,
                    'target' => '/home/rstudio/uploads'
                );
                
                $volumes = [$uploadsVolume['source'] => $uploadsVolume['target']];

                $rstudioSessionResponse = $this->sessionManagerInterface->createSession($project->id, "rstudio", $volumes);
                $this->addLog("rstudioSessionResponse: ".print_r($rstudioSessionResponse, true), "debug");
                $rstudioSessionResponseDecoded = json_decode($rstudioSessionResponse->body);
                $rstudioSessionId = $rstudioSessionResponseDecoded->sessionAccessCode;
                $this->addLog("rstudioSessionId: ".$rstudioSessionId, "debug");
                
                //2. Generate a new empty emu-db in container git dir
                $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/local/bin/R", "-f", "/rscripts/createEmuDb.r"]);

                //Just about here we want to include any uploaded files
                $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/local/bin/R", "-f", "/rscripts/importWavFiles.r"]);

                //Create a generic bundle-list for all bundles
                $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/local/bin/R", "-f", "/rscripts/createBundleList.r"]);

                $cmdOutput = $this->sessionManagerInterface->runCommandInSession($rstudioSessionId, ["/usr/bin/bash", "-c", "cp -R /home/rstudio/default_emuDB/* /home/rstudio/project/"]);
                
                //3. Commit & push
                $cmdOutput = $this->sessionManagerInterface->commitSession($rstudioSessionId);
                //addLog("commit-cmd-output: ".print_r($cmdOutput, true), "debug");
                //4. Shutdown container
                $cmdOutput = $this->sessionManagerInterface->delSession($rstudioSessionId);
                //addLog("session-del-cmd-output: ".print_r($cmdOutput, true), "debug");
                
            }
        }
    
        $ar = new ApiResponse($response['code'], $response['body']);
        return $ar->toJSON();
    }
    
    function deleteGitlabProject($projectId) {
        global $gitlabAddress, $gitlabAccessToken;
    
        $gitlabUsername = $this->getGitLabUsername($_SESSION['email']);
        $gitlabApiRequest = $gitlabAddress."/api/v4/projects/".$projectId."?private_token=".$gitlabAccessToken;
        
        $response = $this->httpRequest("DELETE", $gitlabApiRequest);
    
        $ar = new ApiResponse($response['code'], $response['body']);
        return $ar->toJSON();
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
