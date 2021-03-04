<?php
require_once 'ApiResponse.class.php';
use GuzzleHttp\Psr7;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\ClientException;

class SessionManagerInterface {
    private $sessionManagerDnsName = "session-manager";
    private $sessionManagerApiEndpoint = "http://session-manager:8080/api";
    
    function __construct($app, $hsApiAccessToken) {
        $this->app = $app;
        $this->hsApiAccessToken = $hsApiAccessToken;
    }

    /** 
    * Function: getSessions
    */
    function getSessions() {
        $this->app->addLog("Call: getSessions()", "debug");
        $sessionManagerApiRequest = $this->sessionManagerApiEndpoint."/sessions/".$_SESSION['gitlabUser']->id;
        $appSessions = $this->app->httpRequest("GET", $sessionManagerApiRequest, ['headers' => ['hs_api_access_token' => $this->hsApiAccessToken]]);
        /*
        $this->app->addLog("here goes the cold water...");
        $this->app->addLog(print_r($appSessions, true), "debug");
        $this->app->addLog(print_r(json_decode($appSessions), true), "debug");
        */
        return json_decode($appSessions['body']);
        
    }

    function fetchGitlabProjectById($projectId) {
        global $gitlabApiRequest, $gitlabAddress, $gitlabAccessToken;
        $this->app->addLog("Call: fetchGitlabProjectById(".$projectId.")", "debug");
        $gitlabApiRequest = $gitlabAddress."/api/v4/projects/".$projectId."?private_token=".$gitlabAccessToken;
        return $this->app->httpRequest("GET", $gitlabApiRequest, ['headers' => ['hs_api_access_token' => $this->hsApiAccessToken]]);
    }

    /**
     * This function should probably be in the parent
     */
    function getGitlabProjectById($projectId) {
        $this->app->addLog("Call: getGitlabProjectById(".$projectId.")", "debug");
        foreach($_SESSION['gitlabProjects'] as $key => $proj) {
            if($proj->id == $projectId) {
                return $proj;
            }
        }
        return false;
    }


    /**
     * Function: createSession
     * 
     * Similar to fetchSession but ALWAYS creates a new session, never returns an existing one.
     */
    function createSession($projectId, $hsApp = "rstudio", $volumes = []) {
        $this->app->addLog("Call: createSession(".$projectId.", ".$hsApp.")", "debug");
        $response = $this->fetchGitlabProjectById($projectId);
        $project = $response['body'];
        
        if($project === false) {
            //No such project!
            $this->app->addLog("No such project in sessionManagerInterface->createSession()", "error");
            return false;
        }

        $sessionManagerApiRequest = $this->sessionManagerApiEndpoint."/session/new/user";
        $options = [
            'headers' => ['hs_api_access_token' => $this->hsApiAccessToken],
            'form_params' => [
                'gitlabUser' => json_encode($_SESSION['gitlabUser']),
                'project' => $project,
                'hsApp' => $hsApp,
                'appSession' => "",
                'volumes' => json_encode($volumes)
            ]
        ];
        $this->app->addLog("Will request:".$sessionManagerApiRequest, "debug");
        $response = $this->app->httpRequest("POST", $sessionManagerApiRequest, $options);



        return new ApiResponse($response['code'], $response['body']);
    }

    /**
     * Function: getSession
     * Creates a container for a new session bases on the specified project. Or returns the currenly active session if it exists.
     */
    function fetchSession($projectId, $hsApp = "rstudio") {
        $this->app->addLog("Call: getSession(".$projectId.", ".$hsApp.")", "debug");
        $response = $this->fetchGitlabProjectById($projectId);
        $project = $response['body'];
        //$project = $this->getGitlabProjectById($projectId);
        
        if($project === false) {
            //No such project!
            $this->app->addLog("No such project in sessionManagerInterface->getSession()", "error");
            return false;
        }

        $hsAppSessionId = "";
        if(array_key_exists($hsApp.'Session', $_COOKIE)) {
            $hsAppSessionId = $_COOKIE[$hsApp.'Session'];
        }

        $sessionManagerApiRequest = $this->sessionManagerApiEndpoint."/session/user";
        $options = [
            'headers' => ['hs_api_access_token' => $this->hsApiAccessToken],
            'form_params' => [
                'gitlabUser' => json_encode($_SESSION['gitlabUser']),
                'project' => $project,
                'hsApp' => $hsApp,
                'appSession' => $hsAppSessionId
            ]
        ];
        $this->app->addLog("Will request:".$sessionManagerApiRequest, "debug");
        $response = $this->app->httpRequest("POST", $sessionManagerApiRequest, $options);

        return new ApiResponse($response['code'], $response['body']);
    }

    /**
     * function: runCommandInSession
     * @param $appSessionId
     * @param $cmd - A command to be run specified as an array, like: ["ls", "-l"]
     */
    function runCommandInSession($appSessionId, $cmd = []) {
        $this->app->addLog("runCommandInSession:".print_r($cmd, true), "debug");
        $sessionManagerApiRequest = $this->sessionManagerApiEndpoint."/session/run";
        if(!is_array($cmd)) {
            $cmd = [$cmd];
        }
        $options = [
            'headers' => ['hs_api_access_token' => $this->hsApiAccessToken],
            'form_params' => [
                'appSession' => $appSessionId,
                'cmd' => json_encode($cmd)
            ]
        ];

        $response = $this->app->httpRequest("POST", $sessionManagerApiRequest, $options);
        $this->app->addLog("runCommandInSession result:".print_r($response, true), "debug");
        return $response;
    }

    function commitSession($appSessionId) {
        $this->app->addLog("Call: commitSession(".$appSessionId.")", "debug");

        $sessionManagerApiRequest = $this->sessionManagerApiEndpoint."/session/".$appSessionId."/commit";
        $response = $this->app->httpRequest("GET", $sessionManagerApiRequest, ['headers' => ['hs_api_access_token' => $this->hsApiAccessToken]]);
        return $response["body"];
    }

    function delSession($appSessionId) {
        $this->app->addLog("Call: delSession(".$appSessionId.")", "debug");
        $sessionManagerApiRequest = $this->sessionManagerApiEndpoint."/session/".$appSessionId."/delete";
        $response = $this->app->httpRequest("GET", $sessionManagerApiRequest, ['headers' => ['hs_api_access_token' => $this->hsApiAccessToken]]);
        return $response["body"];
    }
}

?>