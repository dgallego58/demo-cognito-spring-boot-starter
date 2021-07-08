package co.com.bancolombia.cognito.service;


import lombok.AllArgsConstructor;

import java.util.List;

@AllArgsConstructor(staticName = "of")
public class LegalEntityAdapter implements AuthService {

    private final CognitoService cognitoService;

    @Override
    public LegalEntity createUser(String username, String email, String password) {
        var result = cognitoService.createUser(username, email, password);
        var usernameCrated = result.username();
        var userStatus = result.userStatusAsString();

        return null;
    }

    @Override
    public List<LegalEntity> getUsersList() {
        cognitoService.getUserList();
        return null;
    }

    @Override
    public List<LegalEntity> getUsersListWithFilter(String filter) {
        return null;
    }

    @Override
    public String signUpUser(String email) {
        return null;
    }

    @Override
    public String signInUser(String username, String password) {
        return null;
    }

    @Override
    public String confirmUser(String username, String confirmation) {
        return null;
    }

    @Override
    public String changePasswordUser(String acessToken, String oldPassword, String newPassword) {
        return null;
    }

    @Override
    public String forgotPassword(String username) {
        return null;
    }

    @Override
    public String resetPassword(String verificationCode, String newPassword, String username) {
        return null;
    }
}
