<?php
require 'vendor/autoload.php';
require 'RstudioRouterInterface.class.php';

$domain = getenv("HIRD_DOMAIN_NAME");
session_set_cookie_params(60*60*8, "/", ".".$domain);
session_start();

$gitlabAddress = "http://gitlab:80";
$gitlabAccessToken = getenv("GIT_API_ACCESS_TOKEN");
$hirdApiAccessToken = getenv("HIRD_API_ACCESS_TOKEN");

$reqPath = $_SERVER['REQUEST_URI'];
$reqMethod = $_SERVER['REQUEST_METHOD'];


class ApiResponse {
    public $code;
    public $body;
    function __construct($code, $body = "") {
        $this->code = $code;
        $this->body = $body;

        http_response_code($this->code);
    }

    function toJSON() {
        return "{ \"code\": ".json_encode($this->code).", \"body\": ".json_encode($this->body)." }";
    }
}

$rstudioRouterInterface = new RStudioRouterInterface();

if($_SESSION['authorized'] !== true) {
    //if user has not passed a valid authentication, don't allow access to this API
    echo "{ 'msg': 'no access' }";
    exit();
}

if($reqMethod == "GET") {
    switch($reqPath) {
        case "/api/v1/magick":
            $out = dumpServerVariables();
        break;
        case "/api/v1/user":
            $out = getGitlabUser();
        break;
        case "/api/v1/session":
            $out = getUserSessionAttributes();
        break;
        case "/api/v1/user/project":
            $out = getGitlabUserProjects();
        break;
        case "/api/v1/signout":
            signOut();
        break;
    }
    echo $out;
}

if($reqMethod == "POST") {
    $postData = json_decode($_POST['data']);

    switch($reqPath) {
        case "/api/v1/getUserAccessToken":
            $out = getUserAccessToken();
        break;
        case "/api/v1/user":
            $out = createGitlabUser();
        break;
        case "/api/v1/user/project":
            //TODO: Perhaps verify that this user has the right to create a new project?
            $out = createGitlabProject();
        break;
        case "/api/v1/rstudio/session/please":
            //FIXME: This should probably be a GET, not a POST
            if(userHasProjectAuthorization($postData->projectId)) {
                $out = $rstudioRouterInterface->getSession($postData->projectId);
            }
            else {
                $ar = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                $out = $ar->toJSON();
            }
        break;
        case "/api/v1/rstudio/save":
            $out = $rstudioRouterInterface->commitSession($postData->rstudioSession);
        break;
        case "/api/v1/rstudio/close":
            $out = $rstudioRouterInterface->delSession($postData->rstudioSession);
        break;
        case "/api/v1/user/project/delete":
            if(userHasProjectAuthorization($postData->projectId)) {
                $out = deleteGitlabProject($postData->projectId);
            }
            else {
                $ar = new ApiResponse(401, array('message' => 'This user does not have access to that project.'));
                $out = $ar->toJSON();
            }
        break;
    }
    echo $out;
}

function userHasProjectAuthorization($projectId) {
    global $gitlabAddress, $gitlabAccessToken, $gitlabUser;

    $arProjects = getGitlabUserProjects();
    $projects = json_decode($arProjects)->body;

    $foundProject = false;
    foreach($projects as $key => $project) {
        if($project->id == $projectId) {
            $foundProject = true;
        }
    }
    return $foundProject;
}

/**
 * Get a Gitlab access token for this user - this is better (from a security standpoint) than using the root access token.
 * 
 * This function does not work - returns a 404 from Gitlab, not sure why atm.
 */
function getUserAccessToken() {
    global $gitlabAddress, $gitlabAccessToken, $gitlabUser;
    $gitlabUsername = getGitLabUsername($_SESSION['email']);
    $gitlabApiRequest = $gitlabAddress."/api/v4/personal_access_tokens?user_id=".$_SESSION['gitlabUser']->id."&private_token=".$gitlabAccessToken;

    $res = httpRequest("GET", $gitlabApiRequest);

    $response = [];
    $response['gitlab_response'] = $res;

    return json_encode($response);
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

function httpRequest($method = "GET", $url, $options = []) {

    $httpClient = new GuzzleHttp\Client();

    $exception = false;
    $response = "";

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

/**
 * For debugging
 */
function dumpServerVariables() {
    echo "SERVER:\n";
    print_r($_SERVER);
    echo "SESSION:\n";
    print_r($_SESSION);
    echo "\n";
    echo getGitLabUsername($_SESSION['email']);
}

if($reqMethod == "DELETE") {
    switch($reqPath) {
    }
}

function getGitLabUsername($email) {
    return str_replace("@", "_at_", $email);
}

function addLog($msg) {
    file_put_contents("/var/log/api/hird-api.log", "[".date("Y-m-d H:i:s")."]\n".$msg."\n", FILE_APPEND);
}

function getUserSessionAttributes() {
    $output = [
        'firstName' => $_SESSION['firstName'],
        'lastName' => $_SESSION['lastName'],
        'fullName' => $_SESSION['firstName']." ".$_SESSION['lastName'],
        'email' => $_SESSION['email'],
        'gitlabUsername' => getGitLabUsername($_SESSION['email'])
    ];

    $ar = new ApiResponse(200, $output);
    return $ar->toJSON();
}

function createGitlabUser() {
    global $gitlabAddress, $gitlabAccessToken;
    
    $gitlabUsername = getGitLabUsername($_SESSION['email']);
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

    $response = httpRequest("POST", $gitlabApiRequest, $options); 

    if($response['code'] == 201) {
        $userApiResponseObject = json_decode(getGitlabUser());
        $gitlabUser = $userApiResponseObject->body;
        $ar = new ApiResponse($response['code'], $gitlabUser);
    }
    else {
        $ar = new ApiResponse($response['code'], $response['body']);
    }

    return $ar->toJSON();
}

function getGitlabUser() {
    global $gitlabAddress, $gitlabAccessToken, $gitlabUser;
    //Gets User info from Gitlab for currently logged in user
    $gitlabUsername = getGitLabUsername($_SESSION['email']);
    $gitlabApiRequest = $gitlabAddress."/api/v4/users?username=".$gitlabUsername."&private_token=".$gitlabAccessToken;

    $response = httpRequest("GET", $gitlabApiRequest);

    $ar = new ApiResponse($response['code']);

    if($response['code'] == 200) {
        $userListJson = $response['body'];
        $userList = json_decode($userListJson);
        if(empty($userList)) {
            //User does not exist, so create it and return it
            $arCreateGitlabUser = createGitlabUser();
            if(json_decode($arCreateGitlabUser)->code == 200) {
                return getGitlabUser();
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

function getGitlabUserProjects() {
    global $gitlabAddress, $gitlabAccessToken, $hirdApiAccessToken;
    //Gets Gitlab projects for currently logged in user

    if(empty($_SESSION['gitlabUser'])) {
        getGitlabUser();
    }

    $gitlabUsername = getGitLabUsername($_SESSION['email']);
    $gitlabApiRequest = $gitlabAddress."/api/v4/users/".$gitlabUsername."/projects?private_token=".$gitlabAccessToken;
    $response = httpRequest("GET", $gitlabApiRequest);
    $projects = json_decode($response['body']);
    $_SESSION['gitlabProjects'] = $projects;
    
    //Also check if any of these projects have an active running session in the rstudio-router via its API
    $gitlabUsername = getGitLabUsername($_SESSION['email']);
    $rstudioRouterApiRequest = "http://rstudio-router:80/api/sessions/".$_SESSION['gitlabUser']->id;
    $rstudioSessionsResponse = httpRequest("GET", $rstudioRouterApiRequest, [
        'headers' => [
            'User-Agent' => 'hird-api/1.0',
            'Accept'     => 'application/json',
            'hird_api_access_token' => $hirdApiAccessToken
        ]
    ]);

    $sessions = json_decode($rstudioSessionsResponse['body']);

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
    global $gitlabAddress, $gitlabAccessToken;
    
    $gitlabApiRequest = $gitlabAddress."/api/v4/projects/user/".$_SESSION['gitlabUser']->id."?private_token=".$gitlabAccessToken;
    
    $postData = json_decode($_POST['data']);
    
    $response = httpRequest("POST", $gitlabApiRequest, [
        'form_params' => $postData
    ]);

    $ar = new ApiResponse($response['code'], $response['body']);
    return $ar->toJSON();
}

function deleteGitlabProject($projectId) {
    global $gitlabAddress, $gitlabAccessToken;

    $gitlabUsername = getGitLabUsername($_SESSION['email']);
    $gitlabApiRequest = $gitlabAddress."/api/v4/projects/".$projectId."?private_token=".$gitlabAccessToken;
    
    $response = httpRequest("DELETE", $gitlabApiRequest);

    $ar = new ApiResponse($response['code'], $response['body']);
    return $ar->toJSON();
}


?>
