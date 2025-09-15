<?php
namespace Etsy;

use GuzzleHttp\Client;

/**
*
*/
class EtsyClient
{
    public $connect_url = "https://www.etsy.com/oauth/connect";
    public $token_url = "https://api.etsy.com/v3/public/oauth/token";
    public $base_url = "https://openapi.etsy.com/v3";
    public $base_path = "/application";
	private $oauth = null;
	private $access_token = null;
	private $authorized = false;
	private $debug = true;

	private $consumer_key = "";
	private $consumer_secret = "";

	function __construct($consumer_key, $consumer_secret)
	{
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;
	}

	public function authorize($access_token, $access_token_secret)
	{
		$this->access_token = $access_token;
		$this->authorized = true;
	}

	public function request($path, $params = array(), $method = 'GET', $json = true)
	{
		if ($this->authorized === false) {
			throw new \Exception('Not authorized. Please, authorize this client with $client->authorize($access_token, $access_token_secret)');
		}
	    try {
            $client = new Client();
            $content_type = 'application/json';
            if ((($method == 'POST') || ($method == 'PUT') || ($method == 'PATCH')) && strtolower($method) !== strtolower('updateListingInventory')) {
                $content_type = 'application/x-www-form-urlencoded';
            }
            $valid_methods = ['get', 'delete', 'patch', 'post', 'put'];
            if (!in_array(strtolower($method), $valid_methods)) {
                throw new \Exception("{$method} is not a valid request method.");
            }

            if (isset($params['file']) || isset($params['image'])) {
                $multi_part = [];
                foreach ($params as $key => $value) {
                    if (in_array($key, ['image','file'])) {
                        $multi_part[] = array(
                            'name' => $key,
                            'contents' => fopen($value, "r")
                        );
                    } else {
                        $multi_part[] = array(
                            'name' => $key,
                            'contents' => $value
                        );
                    }
                }
                $multi_part[] = ['name' => 'Content-Type', 'contents' => $content_type];
                $response = $client->{strtolower($method)}(
                    $this->base_url . $this->base_path . $path,
                    [
                        'multipart' => $multi_part,
                        'headers' => [
                            'x-api-key' => $this->consumer_key,
                            'Authorization' => "Bearer " . $this->access_token
                        ]
                    ]
                );
            } else {
                $response = $client->{strtolower($method)}(
                    $this->base_url . $this->base_path . $path,
                    [
                        'form_params' => $params,
                        'headers' => [
                            'Content-Type' => $content_type,
                            'x-api-key' => $this->consumer_key,
                            'Authorization' => "Bearer " . $this->access_token
                        ]
                    ]
                );
            }
            $body = $response->getBody()->getContents();
            return json_decode($body, !$json);
	    } catch (\OAuthException $e) {
	        throw new EtsyRequestException($e, $this->oauth, $params);
	    }
	}

	public function getRequestToken(array $extra = array())
	{
	    $url = $this->base_url . "/oauth/request_token";
	    $callback = 'oob';
	    if (isset($extra['scope']) && !empty($extra['scope']))
	    {
	    	$url .= '?scope=' . urlencode($extra['scope']);
	    }

	    if (isset($extra['callback']) && !empty($extra['callback']))
	    {
	    	$callback = $extra['callback'];
	    }
	    try {
		return $this->oauth->getRequestToken($url, $callback, 'GET');
	    } catch (\OAuthException $e) {
	        throw new EtsyRequestException($e, $this->oauth);
	    }

	    return null;
	}

	public function getAccessToken($verifier)
	{
	    try {
			return $this->oauth->getAccessToken($this->base_url . "/oauth/access_token", null, $verifier, 'GET');
	    } catch (\OAuthException $e) {
	        throw new EtsyRequestException($e, $this->oauth);
	    }

	    return null;
	}

	public function getConsumerKey()
	{
		return $this->consumer_key;
	}

	public function getConsumerSecret()
	{
		return $this->consumer_secret;
	}

	public function getLastResponseHeaders(){
        	return $this->oauth->getLastResponseHeaders();
    	}

	public function setDebug($debug)
	{
		$this->debug = $debug;
	}

    /*
     * Start
     * Added new functions for authorization process to avoid multiple sdks
     * rhyshall
     * */

    /**
     * Generates the Etsy authorization URL. Your user will use this URL to authorize access for your API to their Etsy account.
     *
     * @param string $redirect_uri
     * @param array $scope
     * @param string $code_challenge
     * @param string $nonce
     * @return string
     */
    public function getAuthorizationUrl(
        string $redirect_uri,
        array $scope,
        $code_challenge,
        $nonce
    ) {
        $params = [
            "response_type" => "code",
            "redirect_uri" => $redirect_uri,
            "scope" => self::prepare($scope),
            "client_id" => $this->consumer_key,
            "state" => $nonce,
            "code_challenge" => $code_challenge,
            "code_challenge_method" => "S256"
        ];
        return $this->connect_url."/?".http_build_query($params);
    }

    /**
     * Requests an authorization token from the Etsy API. Also returns the refresh token.
     *
     * @param string $redirect_uri
     * @param string $code
     * @param string $verifier
     * @return array
     */
    public function requestAccessToken(
        $redirect_uri,
        $code,
        $verifier
    ) {
        $params = [
            "grant_type" => "authorization_code",
            "client_id" => $this->consumer_key,
            "redirect_uri" => $redirect_uri,
            'code' => $code,
            'code_verifier' => $verifier
        ];
        // Create a GuzzleHttp client.
        $client = new Client();
        try {
            $response = $client->post($this->token_url, ['form_params' => $params]);
            $response = json_decode($response->getBody()->getContents(), true);
            return $response;
        }
        catch(\Exception $e) {
            $this->handleAcessTokenError($e);
        }
    }

    /**
     * Uses the refresh token to fetch a new access token.
     *
     * @param string $refresh_token
     * @return array
     */
    public function refreshAccessToken(
        string $refresh_token
    ) {
        $params = [
            'grant_type' => 'refresh_token',
            'client_id' => $this->consumer_key,
            'refresh_token' => $refresh_token
        ];
        // Create a GuzzleHttp client.
        $client = new Client();
        try {
            $response = $client->post($this->token_url, ['form_params' => $params]);
            $response = json_decode($response->getBody()->getContents(), false);

            //@todo:: here we can return access_token and refresh_token
            return [
                'access_token' => $response->access_token,
                'refresh_token' => $response->refresh_token
            ];
        }
        catch(\Exception $e) {
            $this->handleAcessTokenError($e);
        }
    }

    /**
     * Exchanges a legacy OAuth 1.0 token for an OAuth 2.0 token.
     *
     * @param string $legacy_token
     * @return array
     */
    public function exchangeLegacyToken(
        string $legacy_token
    ) {
        $params = [
            "grant_type" => "token_exchange",
            "client_id" => $this->consumer_key,
            "legacy_token" => $legacy_token
        ];
        // Create a GuzzleHttp client.
        $client = new Client();
        try {
            $response = $client->post($this->token_url, ['form_params' => $params]);
            $response = json_decode($response->getBody()->getContents(), false);
            return [
                'access_token' => $response->access_token,
                'refresh_token' => $response->refresh_token
            ];
        }
        catch(\Exception $e) {
            $this->handleAcessTokenError($e);
        }
    }


    /**
     * Handles OAuth errors.
     *
     * @param Exception $e
     * @return void
     * @throws Etsy\Exception\OAuthException
     */
    private function handleAcessTokenError(\Exception $e) {
        $response = $e->getResponse();
        if (is_null($response)){
            $status_code = $e->getCode();
            $error_msg = "with error \"{$e->getMessage()}\"";
        } else {
            $body = json_decode($response->getBody()->getContents(), false);
            $status_code = $response->getStatusCode();
            $error_msg = "with error \"{$body->error}\"";

            if($body && isset($body->error_description)) {
                $error_msg .= "and message \"{$body->error_description}\"";
            }
        }

        throw new \Exception(
            "Received HTTP status code [$status_code] {$error_msg} when requesting access token."
        );
    }

    /**
     * Generates a random string to act as a nonce in OAuth requests.
     *
     * @param int $bytes
     * @return string
     */
    public function createNonce(int $bytes = null) {
        if (!$bytes) {
            $bytes = 12;
        }
        return bin2hex(random_bytes($bytes));
    }

    /**
     * Generates a PKCE code challenge for use in OAuth requests. The verifier will also be needed for fetching an acess token.
     *
     * @return array
     */
    public function generateChallengeCode() {
        // Create a random string.
        $string = $this->createNonce(32);
        // Base64 encode the string.
        $verifier = $this->base64Encode(
            pack("H*", $string)
        );
        // Create a SHA256 hash and base64 encode the string again.
        $code_challenge = $this->base64Encode(
            pack("H*", hash("sha256", $verifier))
        );
        return [$verifier, $code_challenge];
    }

    /**
     * URL safe base64 encoding.
     *
     * @param string $string
     * @return string
     */
    private function base64Encode($string) {
        return strtr(
            trim(
                base64_encode($string),
                "="
            ),
            "+/", "-_"
        );
    }

    public static function getAllScopes() {
        return [
            "address_r", "address_w", "billing_r", "cart_r", "cart_w", "email_r", "favorites_r", "favorites_w", "feedback_r", "listings_d", "listings_r", "listings_w", "profile_r", "profile_w", "recommend_r", "recommend_w", "shops_r", "shops_w", "transactions_r", "transactions_w"
        ];
    }

    /**
     * Prepares an array of scopes.
     *
     * @param string|array $scopes
     * @return string
     */
    public static function prepare($scope) {
        if(is_array($scope)) {
            $scope = implode(
                " ",
                array_map("trim", array_filter($scope))
            );
        }
        return $scope;
    }

    /*
	 * END
	 * Added new functions for authorization process to avoid multiple sdks
	 * rhyshall
	 * */

}

/**
*
*/
class EtsyResponseException extends \Exception
{
	private $response = null;

	function __construct($message, $response = array())
	{
		$this->response = $response;

		parent::__construct($message);
	}

	public function getResponse()
	{
		return $this->response;
	}
}

/**
*
*/
class EtsyRequestException extends \Exception
{
	private $lastResponse;
	private $lastResponseInfo;
	private $lastResponseHeaders;
	private $debugInfo;
	private $exception;
	private $params;

	function __construct($exception, $oauth, $params = array())
	{
		$this->lastResponse = $oauth->getLastResponse();
		$this->lastResponseInfo = $oauth->getLastResponseInfo();
		$this->lastResponseHeaders = $oauth->getLastResponseHeaders();
		$this->debugInfo = $oauth->debugInfo;
		$this->exception = $exception;
		$this->params = $params;

		parent::__construct($this->buildMessage(), 1, $exception);
	}

	private function buildMessage()
	{
		return $this->exception->getMessage().": " .
			print_r($this->params, true) .
			print_r($this->lastResponse, true) .
			print_r($this->lastResponseInfo, true) .
			// print_r($this->lastResponseHeaders, true) .
			print_r($this->debugInfo, true);
	}

	public function getLastResponse()
	{
		return $this->lastResponse;
	}

	public function getLastResponseInfo()
	{
		return $this->lastResponseInfo;
	}

	public function getLastResponseHeaders()
	{
		return $this->lastResponseHeaders;
	}

	public function getDebugInfo()
	{
		return $this->debugInfo;
	}

	public function getParams()
	{
		return $this->params;
	}

	public function __toString()
	{
		return __CLASS__ . ": [{$this->code}]: ". $this->buildMessage();
	}
}
