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
            'exp' => time() + 900, // 15��
        ];
        return \Firebase\JWT\JWT::encode($payload, $this->jwt_secret_key, 'HS256');
    }

    public function generateRefreshToken($user_id) {
        $payload = [
            'user_id' => $user_id,
            'exp' => time() + 2592000, // 30��
        ];
        return \Firebase\JWT\JWT::encode($payload, $this->jwt_secret_key, 'HS256');
    }

    public function refreshAccessToken($refresh_token) {
        // �������� ��ū�� ���ڵ��մϴ�.
        try {
            $decoded = \Firebase\JWT\JWT::decode($refresh_token, $this->jwt_secret_key, array('HS256'));
        } catch (Exception $e) {
            return new WP_Error('invalid_refresh_token', '��ȿ���� ���� �������� ��ū�Դϴ�.', array('status' => 401));
        }

        // �������� ��ū�� ��ȿ���� Ȯ���մϴ�.
        $current_time = time();
        if (isset($decoded->exp) && $decoded->exp < $current_time) {
            return new WP_Error('refresh_token_expired', '�������� ��ū�� ����Ǿ����ϴ�.', array('status' => 401));
        }

        // Access Token�� ���� �����Ͽ� ��ȯ�մϴ�.
        $user_id = $decoded->user_id;
        $access_token = $this->generateAccessToken($user_id);

        return $access_token;
    }
}