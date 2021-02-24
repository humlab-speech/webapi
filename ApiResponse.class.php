<?php
/**
 * Class: ApiResponse
 * This is the response we are sending back to the webclient, it is not the response we get from the Gitlab API, or the AppRouter
 */
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
?>