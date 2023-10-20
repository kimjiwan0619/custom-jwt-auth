<?php
class TokenGenerator {

    public function __construct($jwt_secret_key) {
        $type = gettype($jwt_secret_key);
        echo 'Data Type of $jwt_secret_key: ' . $type;

        $this->jwt_secret_key = $jwt_secret_key;
    }

    public function generateAccessToken($user_id) {
        $payload = [
            'user_id' => $user_id,
            'exp' => time() + 900, // 15분
        ];
        return \Firebase\JWT\JWT::encode($payload, $this->jwt_secret_key, 'HS256');
    }

    public function generateRefreshToken($user_id) {
        $payload = [
            'user_id' => $user_id,
            'exp' => time() + 2592000, // 30일
        ];
        return \Firebase\JWT\JWT::encode($payload, $this->jwt_secret_key, 'HS256');
    }

    public function refreshAccessToken($refresh_token) {
        // 리프레시 토큰을 디코딩합니다.
        try {
            $decoded = \Firebase\JWT\JWT::decode($refresh_token, $this->jwt_secret_key, array('HS256'));
        } catch (Exception $e) {
            return new WP_Error('invalid_refresh_token', '유효하지 않은 리프레시 토큰입니다.', array('status' => 401));
        }

        // 리프레시 토큰의 유효성을 확인합니다.
        $current_time = time();
        if (isset($decoded->exp) && $decoded->exp < $current_time) {
            return new WP_Error('refresh_token_expired', '리프레시 토큰이 만료되었습니다.', array('status' => 401));
        }

        // Access Token을 새로 생성하여 반환합니다.
        $user_id = $decoded->user_id;
        $access_token = $this->generateAccessToken($user_id);

        return $access_token;
    }
}