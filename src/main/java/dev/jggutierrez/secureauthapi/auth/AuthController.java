package dev.jggutierrez.secureauthapi.auth;

import dev.jggutierrez.secureauthapi.user.User;
import dev.jggutierrez.secureauthapi.user.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {

        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new IllegalArgumentException("Email already in use");
        }

        User user = new User();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password())); // ✅ hash
        user.setRole("USER");

        userRepository.save(user);

        return new RegisterResponse(user.getId(), user.getEmail(), user.getRole());
    }

    public record RegisterRequest(
            @Email @NotBlank String email,
            @NotBlank @Size(min = 6) String password
    ) {}

    public record RegisterResponse(Long id, String email, String role) {}
}
