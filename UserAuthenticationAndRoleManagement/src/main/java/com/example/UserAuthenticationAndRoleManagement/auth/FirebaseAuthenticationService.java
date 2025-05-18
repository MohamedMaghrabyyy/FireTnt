package com.example.UserAuthenticationAndRoleManagement.auth;

import com.example.Notifications.Notification.DTO.CreateNotificationDTO;

import com.example.Notifications.Notification.Notification;
import com.example.UserAuthenticationAndRoleManagement.User.Role;
import com.example.UserAuthenticationAndRoleManagement.User.User;
import com.example.UserAuthenticationAndRoleManagement.User.UserRepository;
import com.example.UserAuthenticationAndRoleManagement.auth.Dto.FirebaseAuthResponse;
import com.example.UserAuthenticationAndRoleManagement.auth.Dto.LoginRequest;
import com.example.UserAuthenticationAndRoleManagement.auth.Dto.LoginResponse;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.google.firebase.auth.SessionCookieOptions;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;


import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Service
public class FirebaseAuthenticationService {
    private final UserRepository userRepo;
    private final WebClient webClient;
    private final String apiKey;
    private final FirebaseAuth firebaseAuth;
    private final RestTemplate restTemplate;
   private final String notificationServiceUrl = "http://localhost:8083/api/notifications/send-welcome-message/json"; // Replace with your Notification service's URL

    public FirebaseAuthenticationService(
            UserRepository userRepo,
            WebClient firebaseAuthWebClient,
            @Value("${firebase.api-key}") String apiKey,
            FirebaseAuth firebaseAuth, RestTemplate restTemplate
    ) {
        this.userRepo     = userRepo;
        this.webClient    = firebaseAuthWebClient;
        this.apiKey       = apiKey;
        this.firebaseAuth = firebaseAuth;
        this.restTemplate = restTemplate;

    }



    public LoginResponse loginWithToken(String idToken) {
        try {
            FirebaseToken decoded = firebaseAuth.verifyIdToken(idToken);
            String firebaseUid = decoded.getUid();

            User u = userRepo.findByFirebaseUid(firebaseUid)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "User not found"
                    ));

            return new LoginResponse(
                    u.getFirebaseUid(),
                    u.getEmail(),
                    idToken,     // optional: echo back
                    null         // no refreshToken, unless passed in
            );

        } catch (FirebaseAuthException e) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid Firebase token",
                    e
            );
        }
    }

//    @Transactional
//    public LoginResponse loginWithEmail(LoginRequest req) {
//        FirebaseAuthResponse resp = webClient.post()
//                .uri(uri -> uri
//                        .path("/accounts:signInWithPassword")
//                        .queryParam("key", apiKey)
//                        .build())
//                .bodyValue(Map.of(
//                        "email", req.getEmail(),
//                        "password", req.getPassword(),
//                        "returnSecureToken", true
//                ))
//                .retrieve()
//                .onStatus(status -> status.value() == 400,
//                        clientResp -> clientResp
//                                .bodyToMono(ObjectNode.class)
//                                .flatMap(body -> {
//                                    String msg = body
//                                            .path("error")
//                                            .path("message")
//                                            .asText("UNKNOWN");
//                                    return Mono.error(
//                                            new ResponseStatusException(HttpStatus.UNAUTHORIZED, msg)
//                                    );
//                                })
//                )
//                .bodyToMono(FirebaseAuthResponse.class)
//                .block();
//
//        String uid = resp.getLocalId();
//        User u = userRepo.findByFirebaseUid(uid)
//                .orElseGet(() -> {
//                    User n = new User();
//                    n.setFirebaseUid(uid);
//                    n.setEmail(resp.getEmail());
//                    return userRepo.save(n);
//                });
//
//        return new LoginResponse(
//                u.getUserId(),
//                u.getEmail(),
//                resp.getIdToken(),
//                resp.getRefreshToken()
//        );
//    }


//    @Transactional
//    public LoginResponse loginWithEmail(LoginRequest req) {
//        // Step 1: Make the API request to Firebase for authentication
//        FirebaseAuthResponse resp = webClient.post()
//                .uri(uri -> uri
//                        .path("/accounts:signInWithPassword")
//                        .queryParam("key", apiKey)
//                        .build())
//                .bodyValue(Map.of(
//                        "email", req.getEmail(),
//                        "password", req.getPassword(),
//                        "returnSecureToken", true
//                ))
//                .retrieve()
//                .onStatus(status -> status.value() == 400,
//                        clientResp -> clientResp
//                                .bodyToMono(ObjectNode.class)
//                                .flatMap(body -> {
//                                    String msg = body
//                                            .path("error")
//                                            .path("message")
//                                            .asText("UNKNOWN");
//                                    return Mono.error(
//                                            new ResponseStatusException(HttpStatus.UNAUTHORIZED, msg)
//                                    );
//                                })
//                )
//                .bodyToMono(FirebaseAuthResponse.class)
//                .block();
//
//        // Step 2: Extract Firebase UID from the response and check if user exists
//        String uid = resp.getLocalId();
//        User u = userRepo.findByFirebaseUid(uid)
//                .orElseGet(() -> {
//                    // Step 3: Create new user if not found
//                    User n = new User();
//                    n.setFirebaseUid(uid);
//                    n.setEmail(resp.getEmail());
//                    n.setPassword(""); // password is empty for Firebase users
//                    n.setRole(Role.GUEST);  // Set the role to GUEST by default
//                    return userRepo.save(n);
//                });
//
//        // Step 4: Return LoginResponse with the user's details and tokens
//        return new LoginResponse(
//                u.getUserId(),
//                u.getEmail(),
//                resp.getIdToken(),
//                resp.getRefreshToken()
//        );
//    }

//    @Transactional
//    public LoginResponse loginWithEmail(LoginRequest req) {
//        if (req.getEmail() == null || req.getEmail().isEmpty()) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot be empty.");
//        }
//
//        if (req.getPassword() == null || req.getPassword().isEmpty()) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password cannot be empty.");
//        }
//
//        // Step 1: Make the API request to Firebase for authentication
//        FirebaseAuthResponse resp = webClient.post()
//                .uri(uri -> uri
//                        .path("/accounts:signInWithPassword")
//                        .queryParam("key", apiKey)
//                        .build())
//                .bodyValue(Map.of(
//                        "email", req.getEmail(),
//                        "password", req.getPassword(),
//                        "returnSecureToken", true
//                ))
//                .retrieve()
//                .onStatus(status -> status.value() == 400,
//                        clientResp -> clientResp
//                                .bodyToMono(ObjectNode.class)
//                                .flatMap(body -> {
//                                    String msg = body
//                                            .path("error")
//                                            .path("message")
//                                            .asText("UNKNOWN");
//                                    return Mono.error(
//                                            new ResponseStatusException(HttpStatus.UNAUTHORIZED, msg)
//                                    );
//                                })
//                )
//                .bodyToMono(FirebaseAuthResponse.class)
//                .block();
//
//        // Step 2: Extract Firebase UID from the response and check if user exists
//        String uid = resp.getLocalId();
//        User u = userRepo.findByFirebaseUid(uid)
//                .orElseGet(() -> {
//                    // Step 3: Create new user if not found
//                    User n = new User();
//                    n.setFirebaseUid(uid);
//                    n.setEmail(resp.getEmail());
//                    n.setPassword(""); // password is empty for Firebase users
//                    n.setRole(Role.GUEST);  // Set the role to GUEST by default
//                    return userRepo.save(n);
//                });
//
//        // Step 4: Return LoginResponse with the user's details and tokens
//        return new LoginResponse(
//                u.getUserId(),
//                u.getEmail(),
//                resp.getIdToken(),
//                resp.getRefreshToken()
//        );
//    }

//    @Transactional
//    public LoginResponse loginWithEmail(LoginRequest req) {
//        // Step 1: Validate the input email and password
//        validateLoginRequest(req);
//
//        // Step 2: Make the API request to Firebase for authentication
//        FirebaseAuthResponse resp = authenticateWithFirebase(req.getEmail(), req.getPassword());
//
//        // Step 3: Extract Firebase UID from the response and check if the user exists
//        String uid = resp.getLocalId();
//        User u = getUserByFirebaseUid(uid);
//
//        // Step 4: Return LoginResponse with the user's details and tokens
//        return createLoginResponse(u, resp);
//    }
//
//    private void validateLoginRequest(LoginRequest req) {
//        if (req.getEmail() == null || req.getEmail().isEmpty()) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot be empty.");
//        }
//
//        if (req.getPassword() == null || req.getPassword().isEmpty()) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password cannot be empty.");
//        }
//    }
//
//    private FirebaseAuthResponse authenticateWithFirebase(String email, String password) {
//        try {
//            return webClient.post()
//                    .uri(uri -> uri
//                            .path("/accounts:signInWithPassword")
//                            .queryParam("key", apiKey)
//                            .build())
//                    .bodyValue(Map.of(
//                            "email", email,
//                            "password", password,
//                            "returnSecureToken", true
//                    ))
//                    .retrieve()
//                    .onStatus(status -> status.value() == 400,
//                            clientResp -> clientResp
//                                    .bodyToMono(ObjectNode.class)
//                                    .flatMap(body -> {
//                                        String msg = body
//                                                .path("error")
//                                                .path("message")
//                                                .asText("UNKNOWN");
//                                        return Mono.error(
//                                                new ResponseStatusException(HttpStatus.UNAUTHORIZED, msg)
//                                        );
//                                    })
//                    )
//                    .bodyToMono(FirebaseAuthResponse.class)
//                    .block();
//        } catch (Exception e) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to authenticate with Firebase", e);
//        }
//    }
//
//    private User getUserByFirebaseUid(String uid) {
//        return userRepo.findByFirebaseUid(uid)
//                .orElseGet(() -> {
//                    // Create a new user if not found
//                    User newUser = new User();
//                    newUser.setFirebaseUid(uid);
//                    newUser.setRole(Role.GUEST);  // Default to GUEST role
//                    return userRepo.save(newUser);
//                });
//    }
//
//    private LoginResponse createLoginResponse(User u, FirebaseAuthResponse resp) {
//        return new LoginResponse(
//                u.getUserId(),
//                u.getEmail(),
//                resp.getIdToken(),
//                resp.getRefreshToken()
//        );
//    }

//    @Transactional
//    public LoginResponse loginWithEmail(LoginRequest req) {
//        if (req.getEmail() == null || req.getEmail().isEmpty()) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot be empty.");
//        }
//
//        if (req.getPassword() == null || req.getPassword().isEmpty()) {
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password cannot be empty.");
//        }
//
//        // Step 1: Make the API request to Firebase for authentication
//        FirebaseAuthResponse resp = webClient.post()
//                .uri(uri -> uri
//                        .path("/accounts:signInWithPassword")
//                        .queryParam("key", apiKey)
//                        .build())
//                .bodyValue(Map.of(
//                        "email", req.getEmail(),
//                        "password", req.getPassword(),
//                        "returnSecureToken", true
//                ))
//                .retrieve()
//                .onStatus(status -> status.value() == 400,
//                        clientResp -> clientResp
//                                .bodyToMono(ObjectNode.class)
//                                .flatMap(body -> {
//                                    String msg = body
//                                            .path("error")
//                                            .path("message")
//                                            .asText("UNKNOWN");
//                                    return Mono.error(
//                                            new ResponseStatusException(HttpStatus.UNAUTHORIZED, msg)
//                                    );
//                                })
//                )
//                .bodyToMono(FirebaseAuthResponse.class)
//                .block();
//
//        // Step 2: Extract Firebase UID from the response and check if user exists
//        String uid = resp.getLocalId();
//        User u = userRepo.findByFirebaseUid(uid)
//                .orElseGet(() -> {
//                    // Step 3: Create new user if not found
//                    User n = new User();
//                    n.setFirebaseUid(uid);
//                    n.setEmail(resp.getEmail());
//                    n.setPassword(""); // password is empty for Firebase users
//                    n.setRole(Role.GUEST);  // Set the role to GUEST by default
//                    // Create a welcome notification for the Guest user
//                    notificationService.create(new CreateNotificationDTO(
//                            n.getUserId(),
//                            n.getEmail(),
//                            "Welcome to FireTnt, " + n.getFirstName() + "!"
//                    ));
//                    return userRepo.save(n);
//                });
//
//        // Step 4: Return LoginResponse with the user's details and tokens
//        return new LoginResponse(
//                u.getUserId(),
//                u.getEmail(),
//                resp.getIdToken(),
//                resp.getRefreshToken()
//        );
//    }


    @Transactional
    public LoginResponse loginWithEmail(LoginRequest req) {
        if (req.getEmail() == null || req.getEmail().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot be empty.");
        }

        if (req.getPassword() == null || req.getPassword().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password cannot be empty.");
        }

        // Step 1: Make the API request to Firebase for authentication
        FirebaseAuthResponse resp = webClient.post()
                .uri(uri -> uri
                        .path("/accounts:signInWithPassword")
                        .queryParam("key", apiKey.trim())
                        .build())
                .bodyValue(Map.of(
                        "email", req.getEmail(),
                        "password", req.getPassword(),
                        "returnSecureToken", true
                ))
                .retrieve()
                .onStatus(status -> status.value() == 400,
                        clientResp -> clientResp
                                .bodyToMono(ObjectNode.class)
                                .flatMap(body -> {
                                    String msg = body
                                            .path("error")
                                            .path("message")
                                            .asText("UNKNOWN");
                                    return Mono.error(
                                            new ResponseStatusException(HttpStatus.UNAUTHORIZED, msg)
                                    );
                                })
                )
                .bodyToMono(FirebaseAuthResponse.class)
                .block();

        // Step 2: Extract Firebase UID from the response and check if user exists
        String uid = resp.getLocalId();
        User u = userRepo.findByFirebaseUid(uid)
                .orElseGet(() -> {
                    User n = new User();
                    n.setFirebaseUid(uid);
                    n.setEmail(resp.getEmail());
                    n.setPassword(""); // password is empty for Firebase users
                    n.setRole(Role.GUEST);  // Set the role to GUEST by default

                    n = userRepo.save(n);


                    CreateNotificationDTO notificationDTO = new CreateNotificationDTO(
                            n.getUserId(),
                            n.getEmail(),
                            "Welcome to FireTnt, " + n.getFirstName() + "!"
                    );

                    // Send HTTP request to Notification service
                    try {
                        restTemplate.postForObject(notificationServiceUrl, notificationDTO, Notification.class);
                    } catch (Exception e) {

                        e.printStackTrace();

                    }

                    return n;
                });

        // Step 5: Return LoginResponse with the user's details and tokens
        return new LoginResponse(
                u.getFirebaseUid(),
                u.getEmail(),
                resp.getIdToken(),
                resp.getRefreshToken()



        );
    }


//    public FirebasePrincipal getPrincipalByUid(String uid) {
//        User u = userRepo.findByFirebaseUid(uid)
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
//        return new FirebasePrincipal(u.getFirebaseUid(), u.getEmail());
//    }

    // in FirebaseAuthenticationService
    public FirebasePrincipal getPrincipalByUid(String uid) {
        System.out.println("Trying to find user with Firebase UID: " + uid);
        User u = userRepo.findByFirebaseUid(uid)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found")
                );
        return new FirebasePrincipal(
                u.getFirebaseUid(),
                u.getEmail(),
                u.getRole()           // pass the enum
        );
    }



    //    private void sendWelcomeEmail(String recipientEmail, String message) {
//        // Create a new notification DTO to send to the Notification service
//        CreateNotificationDTO notificationDTO = new CreateNotificationDTO();
//        notificationDTO.setRecipientEmail(recipientEmail);
//        notificationDTO.setMessage(message);
//
//        // Send a POST request to the Notification service
//        restTemplate.postForObject(notificationServiceUrl, notificationDTO, Notification.class);
//    }
//private void sendWelcomeEmail(User user) {
//    // Create the request body for the Notification service
//    Map<String, Object> notificationRequest = new HashMap<>();
//    notificationRequest.put("recipientEmail", user.getEmail());
//    notificationRequest.put("message", "Welcome " + user.getFirstName() + " " + user.getLastName() + ", you're successfully logged in!");
//
//    // Make a POST request to the Notification service to send the email
//    restTemplate.postForObject(notificationServiceUrl, notificationRequest, String.class);
//}

    @Transactional
    public void logout(String idToken) {
        try {
            FirebaseToken decoded = firebaseAuth.verifyIdToken(idToken);
            firebaseAuth.revokeRefreshTokens(decoded.getUid());
        } catch (FirebaseAuthException e) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Could not revoke tokens",
                    e
            );
        }
    }

    public String createSessionCookie(String idToken) {
        try {
            // session valid for 5 days
            long expiresIn = Duration.ofDays(5).toMillis();
            SessionCookieOptions options = SessionCookieOptions.builder()
                    .setExpiresIn(expiresIn)
                    .build();
            return firebaseAuth.createSessionCookie(idToken, options);
        } catch (FirebaseAuthException e) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Failed to create session cookie",
                    e
            );
        }
    }
    /**
     * Verify the session cookie, checking revocation status.
     * Returns the decoded FirebaseToken on success.
     */
    public FirebaseToken verifySession(String sessionCookie) {
        try {
            return firebaseAuth.verifySessionCookie(sessionCookie, /* checkRevoked= */ true);
        } catch (FirebaseAuthException e) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid or revoked session cookie",
                    e
            );
        }
    }

    public void clearSession(String sessionCookie) {
        try {
            FirebaseToken decoded = firebaseAuth.verifySessionCookie(sessionCookie, true);
            firebaseAuth.revokeRefreshTokens(decoded.getUid());
        } catch (FirebaseAuthException e) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Could not clear session",
                    e
            );
        }
    }

    // add this method
    public String refreshIdToken(String refreshToken) {
        var form = new LinkedMultiValueMap<String,String>();
        form.add("grant_type","refresh_token");
        form.add("refresh_token", refreshToken);

        var resp = webClient.post()
                .uri(uri -> uri
                        .path("/token")
                        .queryParam("key", apiKey)
                        .build()
                )
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(com.fasterxml.jackson.databind.JsonNode.class)
                .block();

        return resp.get("id_token").asText();
    }


    public void assignAdminRole(String firebaseUid) throws FirebaseAuthException {
        Map<String,Object> claims = new HashMap<>();
        claims.put("role","ADMIN");
        firebaseAuth.setCustomUserClaims(firebaseUid, claims);
    }


}