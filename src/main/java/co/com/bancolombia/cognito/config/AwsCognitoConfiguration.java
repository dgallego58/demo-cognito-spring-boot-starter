package co.com.bancolombia.cognito.config;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.Scope;
import software.amazon.awssdk.auth.credentials.WebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

@Lazy
@Configuration
@EnableConfigurationProperties(value = {CognitoProperties.class})
public class AwsCognitoConfiguration {

    @Bean
    @Profile({"!local"})
    @Scope(scopeName = ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public CognitoIdentityProviderClient cognitoIdentityProviderClient() {
        return CognitoIdentityProviderClient.builder()
                .credentialsProvider(WebIdentityTokenFileCredentialsProvider.create())
                .region(Region.US_EAST_1)
                .build();
    }

    @Bean
    @Profile({"local"})
    @Scope(scopeName = ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public CognitoIdentityProviderClient localCognitoIdentityProviderClient() {
        return CognitoIdentityProviderClient.builder()
                .region(Region.US_EAST_1)
                .build();
    }

}
