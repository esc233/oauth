package cn.hs.client;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.Base64;

public class HttpClient {
    public static void main(String[] args) {
        // 基础信息
        String clientId = "demo-client";
        String clientSecret = "demo-secret";
        String authServerUrl = "http://127.0.0.1:8080/oauth2/authorize";
        String redirectUri = "http://127.0.0.1:8080/login/oauth2/code/demo-client";
        String scope = "read";

        // 构造 Basic Authentication Header
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        String authorizationHeader = "Basic " + encodedCredentials;

        // 构造 URL 带参数
        HttpUrl url = HttpUrl.parse(authServerUrl).newBuilder()
                .addQueryParameter("response_type", "code")
                .addQueryParameter("client_id", clientId)
                .addQueryParameter("redirect_uri", redirectUri)
                .addQueryParameter("scope", scope)
                .build();

        // 创建 OkHttpClient 实例
        OkHttpClient client = new OkHttpClient();

        // 构造请求
        Request request = new Request.Builder()
                .url(url)
                .header("Authorization", authorizationHeader) // 添加 Basic Auth Header
                .get()
                .build();

        // 发送请求并处理响应
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful()) {
                System.out.println("Response Code: " + response.code());
                System.out.println("Response Body: " + response.body().string());
            } else {
                System.err.println("Request failed: " + response.code() + " - " + response.message());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
