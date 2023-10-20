<?php
/*
Plugin Name: Custom JWT Authentication
Description: Custom JWT authentication and authorization for REST API.
Version: 1.0
Author: Your Name
*/

// Composer Autoloader�� �ε�
require_once plugin_dir_path(__FILE__) . 'vendor/autoload.php';
require_once(plugin_dir_path(__FILE__) . 'wp-includes/custom-jwt-token.php');

// Define your JWT secret key
$jwt_secret_key = 'secretkey'; // Store securely

function custom_login_action($user_login, $user) {
    // ����ڰ� �α����� �� ����� �۾�
    global $jwt_secret_key;

    // Access Token �� Refresh Token�� �����ϰ� ��ȯ
    $tokenGenerator = new TokenGenerator($jwt_secret_key);
    $access_token = $tokenGenerator->generateAccessToken($user_id);
    $refresh_token = $tokenGenerator->generateRefreshToken($user_id);

    // Access Token �� Refresh Token�� ����ڿ��� �����ϴ� ��� (��: ��Ű, ��� ��)
    setcookie('access_token', $access_token, time() + 900, '/'); // Access Token�� ���� �ð��� 15��
    setcookie('refresh_token', $refresh_token, time() + 2592000, '/'); // Refresh Token�� ���� �ð��� 30��
}
add_action('wp_login', 'custom_login_action', 10, 2);

function register_custom_api_routes() {
    register_rest_route('custom-jwt-auth/v1', '/token', array(
        'methods' => 'GET',
        'callback' => 'custom_endpoint_callback',
    ));
}
add_action('rest_api_init', 'register_custom_api_routes');



function custom_endpoint_callback($request) {
    // Authorization ���
    $authorization_header = $request->get_header('Authorization');
    //var_dump($authorization_header);
    if (empty($authorization_header)) {
        return new WP_Error('authorization_required', 'Authorization ����� �ʿ��մϴ�.', array('status' => 401));
    }

    // "Bearer" ������ ���� ��ū ���ڿ��� ����
    $jwt = str_replace('Bearer ', '', $authorization_header);

    // JWT�� ���ڵ��մϴ�. ���⼭�� Firebase JWT ���̺귯���� ���
    $key = 'secretkey'; // JWT ���� ����� ��� Ű
    //var_dump($key);
    //var_dump($jwt);
    try {
        $decoded = \Firebase\JWT\JWT::decode($jwt, $key, array('HS256'));
        var_dump($decoded);
    } catch (Exception $e) {
        return new WP_Error('invalid_token', '��ȿ���� ���� JWT ��ū�Դϴ�.', array('status' => 401));
    }

    // Access Token�� ���� �ð��� Ȯ��
    $current_time = time();
    if (isset($decoded->exp) && $decoded->exp < $current_time) {
        // Access Token�� ����Ǿ����� �������� ��ū�� ����Ͽ� ���ο� Access Token�� �߱�
        $refresh_token = $_COOKIE['refresh_token'];
        $new_access_token = refresh_access_token($refresh_token);

        if (is_wp_error($new_access_token)) {
            return $new_access_token;
        }

        // ���ο� Access Token�� Ŭ���̾�Ʈ���� ��ȯ
        setcookie('access_token', $new_access_token, time() + 900, '/');
    }

    // ������ �㰡�Ǹ� ��û ó��
    $response_data = array(
        'message' => '��û�� �㰡�Ǿ����ϴ�.',
        'user' => $user,
    );

    return new WP_REST_Response($response_data, 200);
}

// ����ڰ� �α׾ƿ��� �� ȣ��Ǵ� ��
function custom_logout_action() {
    // ���� ����� ���� ��������
    $current_user = wp_get_current_user();

    // ����� ID�� ������� ��ū ������ ����
    // �� �ڵ�� ��ū �����͸� �����ͺ��̽� �Ǵ� ����ҿ��� �����ϴ� �����Դϴ�.
    // ���� ��ū ���� ����� ���� �ڵ带 �����ؾ� �� �� �ֽ��ϴ�.

    // Access Token ����
    delete_user_meta($current_user->ID, 'access_token');

    // Refresh Token ���� (�ִ� ���)
    delete_user_meta($current_user->ID, 'refresh_token');

    // �α׾ƿ� ���� ���𷺼�
    wp_redirect(home_url());
    exit;
}
add_action('wp_logout', 'custom_logout_action');