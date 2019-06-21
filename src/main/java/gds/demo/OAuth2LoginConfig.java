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
 * 
 * 说明：Jhipster支持注册多个ClientRegistration，以便同时支持用户选择不同的身份提供者登录。
 * Jhipster缺省生成的Oauth/OpenId应用代码中使用了RegistrationId为oidc的ClientRegistration。
 * 如果要修改这个RegistrationId为其它值，需要修改三个文件中硬编码的oidc为新的RegistrationId：
 * 1、本类中的ClientRegistration.withRegistrationId("oidc")
 * 2、xx.xx.web.rest.LogoutResource类的构造函数的实现：this.registration = registrations.findByRegistrationId("oidc");
 * 3、src/main/webapp/app/shared/util/url-utils.ts文件中的return `//${location.hostname}${port}${location.pathname}oauth2/authorization/oidc`;
 * 
 * 此外，还需要在身份提供者中注册应用（服务提供者）时的回调URL中做相应的修改。如：在wso2is中注册服务提供者时，指定的回调URL如下：
<pre>
 * regexp=(http://192.168.200.24:8080/login/oauth2/code/oidc|http://localhost:9000/login/oauth2/code/oidc|http://192.168.200.24:8080|http://localhost:9000)
</pre>
 * 如果要配置多个ClientRegistration，且同时支持多个不同的身份提供者登录，需要将 * url-utils.ts文件中的
<pre>
  return `//${location.hostname}${port}${location.pathname}oauth2/authorization/oidc`;
</pre>
 * 修改为
<pre>
  return `//${location.hostname}${port}${location.pathname}login`;
</pre>
 * 这样，但用户点击登录时，系统自动跳转到spring安全生成的登录页面中，该页面上列出了全部已注册的ClientRegistration，用户选择后就可以使用不同的身份登录本应用了
 * 
 * 为了方便部署，我们可以使用如下的环境变量来在系统外部配置系统参数：
<pre>
	export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OIDC_CLIENT_ID=rac6pHBoA96Qv6vSOB8fsEhXD5Ya
	export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OIDC_CLIENT_SECRET=LlL6hGNeKfJ9Dolve2aWdjTml3oa
	export SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OIDC_CLIENT_NAME=OIDC测试应用
	export SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_OIDC_ISSUER_URI=https://is.cd.mtn:9443/oauth2/token
	export SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_OIDC_LOGOUT_URI=https://is.cd.mtn:9443/oidc/logout
	export SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_OIDC_AUTHORIZATION_URI=https://is.cd.mtn:9443/oauth2/authorize
	export SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_OIDC_TOKEN_URI=https://is.cd.mtn:9443/oauth2/token
	export SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_OIDC_USER_INFO_URI=https://is.cd.mtn:9443/oauth2/userinfo
	export SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_OIDC_JWK_SET_URI=https://is.cd.mtn:9443/oauth2/jwks
</pre>

 * 为了方便在IDE中调试运行，我们可以修改/src/main/resources/config/application.yml中spring:security:oauth2:client的参数如下：
 * 
<pre>
 spring:
  ......
  security:
    oauth2:
      client:
        provider:
          oidc:
            issuer-uri: https://is.cd.mtn:9443/oauth2/token
            logout-uri: https://is.cd.mtn:9443/oidc/logout
            authorization-uri: https://is.cd.mtn:9443/oauth2/authorize
            token-uri: https://is.cd.mtn:9443/oauth2/token
            user-info-uri: https://is.cd.mtn:9443/oauth2/userinfo
            jwk-set-uri: https://is.cd.mtn:9443/oauth2/jwks
        registration:
          oidc:
            client-id: rac6pHBoA96Qv6vSOB8fsEhXD5Ya
            client-secret: LlL6hGNeKfJ9Dolve2aWdjTml3oa
            client-name: OIDC测试应用
 * </pre>
 * 
 * @author wangf
 *
 */
@Configuration
public class OAuth2LoginConfig {
    private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.oidc.";
    private static String PROVIDER_PROPERTY_KEY = "spring.security.oauth2.client.provider.oidc.";
    @Autowired
    private Environment env;

    @Bean
    public ClientRegistrationRepository
    clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.buildClientRegistration());
    }

    private ClientRegistration buildClientRegistration() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("end_session_endpoint", env.getProperty(PROVIDER_PROPERTY_KEY + "logout-uri")); 
        return ClientRegistration.withRegistrationId("oidc")           //这是应用的注册Id，这个id就是回调Url中的{registrationId}，命名：应用的英文名称
                .clientName(env.getProperty(CLIENT_PROPERTY_KEY + "client-name","OIDC应用"))   //这是应用的显示名称，应用注销后会显示在引导用户重新登录的页面上        		
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
                 .build();
    }
}