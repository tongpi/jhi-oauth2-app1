package gds.demo;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

/**
 * 添加OAuth2LoginConfig类以使用特定于wso2的详细信息和将用于登录的已注册OAuth2客户端配置InMemoryCenterRegistrationRepository.
 * @author wangf
 *
 */
@Configuration
public class OAuth2LoginConfig {
    private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.wso2.";
    private static String PROVIDER_PROPERTY_KEY = "spring.security.oauth2.client.provider.wso2.";
    @Autowired
    private Environment env;

    @Bean
    public ClientRegistrationRepository
    clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.WSO2ClientRegistration());
    }

    private ClientRegistration WSO2ClientRegistration() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("end_session_endpoint", "https://is.cd.mtn:9443/oidc/logout");    	
        return ClientRegistration.withRegistrationId("oidc")           //这是应用的注册Id，这个id就是回调Url中的{registrationId}，命名：应用的英文名称
                .clientId(env.getProperty(CLIENT_PROPERTY_KEY + "client-id"))
                .clientSecret(env.getProperty(CLIENT_PROPERTY_KEY + "client-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")  //IS中添加的服务提供者的入站认证配置下的OAuth/OpenId连接配置中的回调Url须根据这个模板来填写
                .scope("openid", "profile", "email", "address", "phone")              //这是本应用期望从IS获取的用户个人信息的用途或范围，登录成功后，系统要求用户确认是否愿意提供这些信息。
                .authorizationUri(env.getProperty(PROVIDER_PROPERTY_KEY + "authorization-uri"))
                .tokenUri(env.getProperty(PROVIDER_PROPERTY_KEY + "token-uri"))
                .userInfoUri(env.getProperty(PROVIDER_PROPERTY_KEY + "user-info-uri"))
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .providerConfigurationMetadata(metadata)
                .jwkSetUri(env.getProperty(PROVIDER_PROPERTY_KEY + "jwk-set-uri"))
                .clientName("jhi-oauth-2-sample-1")   //这是应用的显示名称，应用注销后会显示在引导用户重新登录的页面上
                .build();
    }
}