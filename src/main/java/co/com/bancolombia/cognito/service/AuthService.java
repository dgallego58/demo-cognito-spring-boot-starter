package co.com.bancolombia.cognito.service;

import java.util.List;

public interface AuthService {

    LegalEntity createUser(String username, String email, String password);

    List<LegalEntity> getUsersList();

    List<LegalEntity> getUsersListWithFilter(String filter);

    String signUpUser(String email);

    String signInUser(String username, String password);

    String confirmUser(String username, String confirmation);

    String changePasswordUser(String acessToken, String oldPassword, String newPassword);

    String forgotPassword(String username);

    String resetPassword(String verificationCode, String newPassword, String username);

}
