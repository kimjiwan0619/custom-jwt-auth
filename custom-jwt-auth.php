<?php
/*
Plugin Name: Custom JWT Authentication
Description: Custom JWT authentication and authorization for REST API.
Version: 1.0
Author: Your Name
*/

// Composer Autoloader를 로드
require_once plugin_dir_path(__FILE__) . 'vendor/autoload.php';
require_once(plugin_dir_path(__FILE__) . 'wp-includes/custom-jwt-token.php');

// Define your JWT secret key
$jwt_secret_key = 'secretkey'; // Store securely

function custom_login_action($user_login, $user) {
    // 사용자가 로그인한 후 실행될 작업
    global $jwt_secret_key;

    // Access Token 및 Refresh Token을 생성하고 반환
    $tokenGenerator = new TokenGenerator($jwt_secret_key);
    $access_token = $tokenGenerator->generateAccessToken($user_id);
    $refresh_token = $tokenGenerator->generateRefreshToken($user_id);

    // Access Token 및 Refresh Token을 사용자에게 전달하는 방법 (예: 쿠키, 헤더 등)
    setcookie('access_token', $access_token, time() + 900, '/'); // Access Token의 만료 시간은 15분
    setcookie('refresh_token', $refresh_token, time() + 2592000, '/'); // Refresh Token의 만료 시간은 30일
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
    // Authorization 헤더
    $authorization_header = $request->get_header('Authorization');
    //var_dump($authorization_header);
    if (empty($authorization_header)) {
        return new WP_Error('authorization_required', 'Authorization 헤더가 필요합니다.', array('status' => 401));
    }

    // "Bearer" 다음에 오는 토큰 문자열을 추출
    $jwt = str_replace('Bearer ', '', $authorization_header);

    // JWT를 디코딩합니다. 여기서는 Firebase JWT 라이브러리를 사용
    $key = 'secretkey'; // JWT 서명에 사용한 비밀 키
    //var_dump($key);
    //var_dump($jwt);
    try {
        $decoded = \Firebase\JWT\JWT::decode($jwt, $key, array('HS256'));
        var_dump($decoded);
    } catch (Exception $e) {
        return new WP_Error('invalid_token', '유효하지 않은 JWT 토큰입니다.', array('status' => 401));
    }

    // Access Token의 만료 시간을 확인
    $current_time = time();
    if (isset($decoded->exp) && $decoded->exp < $current_time) {
        // Access Token이 만료되었으면 리프레시 토큰을 사용하여 새로운 Access Token을 발급
        $refresh_token = $_COOKIE['refresh_token'];
        $new_access_token = refresh_access_token($refresh_token);

        if (is_wp_error($new_access_token)) {
            return $new_access_token;
        }

        // 새로운 Access Token을 클라이언트에게 반환
        setcookie('access_token', $new_access_token, time() + 900, '/');
    }

    // 권한이 허가되면 요청 처리
    $response_data = array(
        'message' => '요청이 허가되었습니다.',
        'user' => $user,
    );

    return new WP_REST_Response($response_data, 200);
}

// 사용자가 로그아웃할 때 호출되는 훅
function custom_logout_action() {
    // 현재 사용자 정보 가져오기
    $current_user = wp_get_current_user();

    // 사용자 ID를 기반으로 토큰 데이터 삭제
    // 이 코드는 토큰 데이터를 데이터베이스 또는 저장소에서 삭제하는 예제입니다.
    // 실제 토큰 관리 방법에 따라 코드를 수정해야 할 수 있습니다.

    // Access Token 삭제
    delete_user_meta($current_user->ID, 'access_token');

    // Refresh Token 삭제 (있는 경우)
    delete_user_meta($current_user->ID, 'refresh_token');

    // 로그아웃 이후 리디렉션
    wp_redirect(home_url());
    exit;
}
add_action('wp_logout', 'custom_logout_action');