package com.example.UserAuthenticationAndRoleManagement.User;
import com.example.UserAuthenticationAndRoleManagement.User.Client.NotificationClient;
import com.example.UserAuthenticationAndRoleManagement.User.DTO.CreateUserDTO;
import com.example.UserAuthenticationAndRoleManagement.User.DTO.NotificationDto;
import com.example.UserAuthenticationAndRoleManagement.auth.FirebasePrincipal;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final NotificationClient notifClient;
    private final FirebaseAuth auth = FirebaseAuth.getInstance();


    public UserService(UserRepository userRepository, NotificationClient notifClient) {
        this.userRepository = userRepository;
        this.notifClient = notifClient;

    }

    @Cacheable("users")
    public List<User> fetchAll() {
        return userRepository.findAll(Sort.by("userId"));
    }

    @Cacheable(value = "users", key = "#id")
    public User fetchById(Long id) {
        return userRepository.findById(id).orElse(null);
    }
    public User fetchByFirebaseUid(String firebaseUid) {
            return userRepository.findByFirebaseUid(firebaseUid)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "User not found"
                    ));
        }


    public Long findUserIdByFirebaseUid(String firebaseUid) {
        return userRepository.findByFirebaseUid(firebaseUid)
                .map(User::getUserId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"
                ));
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "User not found"
                        ));
    }

    @Transactional
    public User createUser(CreateUserDTO dto) {

        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Email " + dto.getEmail() + " is already registered. Please use a different email."
            );
        }

        try {
            // Check Firebase
            auth.getUserByEmail(dto.getEmail());
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Email " + dto.getEmail() + " is already registered in Firebase"
            );

        } catch (FirebaseAuthException e) {
            if (!"USER_NOT_FOUND".equals(e.getAuthErrorCode().name())) {
                throw new ResponseStatusException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to verify email in Firebase",
                        e
                );
            }
        }

        try {
            // Create Firebase user
            var req = new UserRecord.CreateRequest()
                    .setEmail(dto.getEmail())
                    .setPassword(dto.getPassword());
            var rec = auth.createUser(req);

            // Create local user
            var u = new User();
            u.setFirebaseUid(rec.getUid());
            u.setEmail(rec.getEmail());
            u.setFirstName(dto.getFirstName());
            u.setLastName(dto.getLastName());
            u.setPhoneNumber(dto.
                    getPhoneNumber());
            u.setPassword(dto.getPassword());
            u.setRole(dto.getRole());  // Set the role here
            return userRepository.save(u);

        } catch (FirebaseAuthException e) {
            if ("EMAIL_ALREADY_EXISTS".equals(e.getAuthErrorCode().name())) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Email " + dto.getEmail() + " is in use on Firebase. Please choose another email.",
                        e
                );
            }
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to create user on Firebase",
                    e
            );
        }
    }




    @CacheEvict(value = "users", allEntries = true)
    @Transactional
    public void deleteUser(Long id) {
        var u = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"
                ));

        try {
            auth.deleteUser(u.getFirebaseUid());
        } catch (FirebaseAuthException e) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "Firebase delete failed",
                    e
            );
        }

        userRepository.deleteById(id);
    }

    public List<NotificationDto> getNotifications(Long userId) {
        var ids = notifClient.fetchIdsByUser(userId);
        return ids.stream()
                .map(notifClient::fetchById)
                .toList();
    }
    public String getCurrentFirebaseUid() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.getPrincipal() instanceof FirebasePrincipal fp) {
            return fp.getUid();
        }

        throw new IllegalStateException("User is not authenticated or invalid principal");
    }
    public String getRoleName(){
       long userId= findUserIdByFirebaseUid(getCurrentFirebaseUid());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"
                ));
        return user.getRole().name();
    }
}
