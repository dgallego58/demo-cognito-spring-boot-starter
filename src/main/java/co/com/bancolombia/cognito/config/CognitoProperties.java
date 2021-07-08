package co.com.bancolombia.cognito.config;

import lombok.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@ConstructorBinding
@Value(staticConstructor = "create")
@ConfigurationProperties(prefix = "networking.cognito")
public class CognitoProperties {

    String userPoolId;
    String clientId;
}
