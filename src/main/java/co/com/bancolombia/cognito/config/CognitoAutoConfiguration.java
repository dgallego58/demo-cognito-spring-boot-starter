package co.com.bancolombia.cognito.config;

import co.com.bancolombia.cognito.service.AuthService;
import co.com.bancolombia.cognito.service.CognitoService;
import co.com.bancolombia.cognito.service.LegalEntityAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

@Import(value = {AwsCognitoConfiguration.class})
public class CognitoAutoConfiguration {

    @Bean
    public AuthService authService(CognitoService cognitoService) {
        return LegalEntityAdapter.of(cognitoService);
    }

}
