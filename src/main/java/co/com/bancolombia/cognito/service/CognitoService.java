package co.com.bancolombia.cognito.service;

import co.com.bancolombia.cognito.config.CognitoProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChangePasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChangePasswordResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmForgotPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmSignUpRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmSignUpResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ForgotPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Slf4j
@Service
public class CognitoService {

    private final CognitoIdentityProviderClient cognitoIdentityProviderClient;
    private final CognitoProperties cognitoProperties;

    public CognitoService(CognitoIdentityProviderClient cognitoIdentityProviderClient,
                          CognitoProperties cognitoProperties) {
        this.cognitoIdentityProviderClient = cognitoIdentityProviderClient;
        this.cognitoProperties = cognitoProperties;
    }

    public static CognitoService from(CognitoIdentityProviderClient cognitoIdentityProviderClient,
                                      CognitoProperties cognitoProperties) {
        return new CognitoService(cognitoIdentityProviderClient, cognitoProperties);
    }

    public static String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        try {
            var mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            log.error("Error en en el calculo del hash de del secreto {}, {}", e.getMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);

        }
    }

    public UserType createUser(String name, String email, String password) {
        UserType resultado = null;
        try {
            AttributeType userAttrs = AttributeType.builder()
                    .name("email")
                    .value(email)
                    .build();

            AdminCreateUserRequest userRequest = AdminCreateUserRequest.builder()
                    .userPoolId(cognitoProperties.getUserPoolId())
                    .username(name)
                    .temporaryPassword(password)
                    .userAttributes(userAttrs)
                    .messageAction("SUPPRESS")
                    .build();

            AdminCreateUserResponse response = cognitoIdentityProviderClient.adminCreateUser(userRequest);

            resultado = response.user();
        } catch (CognitoIdentityProviderException e) {
            log.error("Error en la creación del usuario {}, {}", e.awsErrorDetails().errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }
        return resultado;
    }

    public boolean signUpUser(String email) {
        var attributeType = AttributeType.builder()
                .name("email")
                .value(email)
                .build();

        List<AttributeType> attrs = new ArrayList<>();
        attrs.add(attributeType);

        try {
            SignUpRequest signUpRequest = SignUpRequest.builder()
                    .userAttributes(attrs)
                    .username(email)
                    .clientId(cognitoProperties.getClientId())
                    .password("RandomPass!")//RandomStringUtils.randomAscii(8))
                    .build();

            SignUpResponse response = cognitoIdentityProviderClient.signUp(signUpRequest);
            return response.userConfirmed();

        } catch (CognitoIdentityProviderException e) {
            log.error("Error en el registro del usuario en cognito {}, {}", e.awsErrorDetails().errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }

    }

    public List<UserType> getUserList() {
        try {
            ListUsersRequest usersRequest = ListUsersRequest.builder()
                    .userPoolId(cognitoProperties.getUserPoolId())
                    .build();
            ListUsersResponse response = cognitoIdentityProviderClient.listUsers(usersRequest);
            List<UserType> resultado = response.users();
            return resultado;
        } catch (CognitoIdentityProviderException e) {
            log.error("Error en obtener la lista de los usuarios {}, {}", e.awsErrorDetails().errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }
    }

    public List<UserType> getUserListWithFilter(String filter) {
        try {
            ListUsersRequest usersRequest = ListUsersRequest.builder()
                    .userPoolId(cognitoProperties.getUserPoolId())
                    .filter(filter)
                    .build();

            ListUsersResponse response = cognitoIdentityProviderClient.listUsers(usersRequest);
            return response.users();
        } catch (CognitoIdentityProviderException e) {
            log.error("Error en obtener la lista de usuarios con filtros {}, {}", e.awsErrorDetails()
                    .errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }
    }

    public String signInUser(String username, String password) {
        try {
            Map<String, String> authParams = new HashMap<>();
            authParams.put("USERNAME", username);
            authParams.put("PASSWORD", password);

            final InitiateAuthRequest authRequest = InitiateAuthRequest
                    .builder()
                    .clientId(cognitoProperties.getClientId())
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(authParams)
                    .build();

            InitiateAuthResponse result = cognitoIdentityProviderClient.initiateAuth(authRequest);
            return result.authenticationResult().accessToken();
        } catch (CognitoIdentityProviderException e) {
            log.error("Error en el ingreso (sign in) del usuario {}, {}", e.awsErrorDetails().errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }

    }

    public String confirmUser(String username, String confirmation) {
        try {

            ConfirmSignUpRequest adminConfirmSignUpRequest = ConfirmSignUpRequest
                    .builder()
                    .clientId(cognitoProperties.getClientId())
                    .confirmationCode(confirmation)
                    .username(username)
                    .build();
            ConfirmSignUpResponse result = cognitoIdentityProviderClient.confirmSignUp(adminConfirmSignUpRequest);
            log.debug("the cognito user Confirmed successfully.");

            return "Cognito email verified";

        } catch (CognitoIdentityProviderException e) {
            log.error("Error en la confirmación del usuario {}, {}", e.awsErrorDetails().errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }
    }

    public String changeUserPassword(String acessToken, String oldPassword, String newPassword) {
        try {
            final ChangePasswordRequest changePasswordRequest = ChangePasswordRequest.builder()
                    .accessToken(acessToken)
                    .previousPassword(oldPassword)
                    .proposedPassword(newPassword)
                    .build();
            ChangePasswordResponse response = cognitoIdentityProviderClient.changePassword(changePasswordRequest);
            return "Contraseña modificada correctamente";
        } catch (CognitoIdentityProviderException e) {
            log.error("Error en el cambio de contraseña del usuario {}, {}", e.awsErrorDetails()
                    .errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }

    }

    public String forgotPassword(String username) {
        try {
            ForgotPasswordRequest forgotPasswordRequest = ForgotPasswordRequest
                    .builder()
                    .clientId(cognitoProperties.getClientId())
                    .username(username)
                    .build();

            cognitoIdentityProviderClient.forgotPassword(forgotPasswordRequest);
        } catch (CognitoIdentityProviderException e) {
            log.error("Error en la solicitud de olvidé mi contraseña {}, {}", e.awsErrorDetails().errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }
        return "Codigo de verificacion enviado correctamente";
    }

    public String resetPassword(String verificationCode, String newPassword, String username) {
        try {
            ConfirmForgotPasswordRequest confirmForgotPasswordRequest = ConfirmForgotPasswordRequest
                    .builder()
                    .clientId(cognitoProperties.getClientId())
                    .confirmationCode(verificationCode)
                    .password(newPassword)
                    .username(username)
                    .build();
            cognitoIdentityProviderClient.confirmForgotPassword(confirmForgotPasswordRequest);
        } catch (CognitoIdentityProviderException e) {
            log.error("Error en la solicitud reiniciar contraseña {}, {}", e.awsErrorDetails().errorMessage(), e);
            //todo cambiar agregar excepciones de cognito a el excel
            throw new RuntimeException(e);
        }
        return "Contraseña cambiada correctamente";
    }


}
