1. _**Structure**:_
src/main/java/com/example/studentmanagement/
├── config/
│   ├── SecurityConfig.java
│   ├── WebMvcConfig.java
│   └── EncryptionConfig.java
├── controller/
│   ├── AuthController.java
│   ├── StudentController.java
│   └── BackupController.java
├── dto/
│   ├── LoginRequest.java
│   ├── StudentDto.java
│   └── ApiResponse.java
├── exception/
│   ├── CustomException.java
│   └── GlobalExceptionHandler.java
├── model/
│   ├── User.java
│   └── Student.java
├── repository/
│   ├── UserRepository.java
│   └── StudentRepository.java
├── security/
│   ├── JwtTokenProvider.java
│   ├── UserPrincipal.java
│   ├── CustomUserDetailsService.java
│   └── JwtAuthenticationFilter.java
├── service/
│   ├── UserService.java
│   ├── StudentService.java
│   ├── EncryptionService.java
│   └── BackupService.java
└── StudentManagementApplication.java



2. _**xml**:_
<dependencies>
    <!-- Spring Boot Starter -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>

    <!-- Database -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.liquibase</groupId>
        <artifactId>liquibase-core</artifactId>
    </dependency>

    <!-- Security -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk15on</artifactId>
        <version>1.70</version>
    </dependency>

    <!-- Encryption -->
    <dependency>
        <groupId>org.jasypt</groupId>
        <artifactId>jasypt</artifactId>
        <version>1.9.3</version>
    </dependency>

    <!-- Utilities -->
    <dependency>
        <groupId>org.modelmapper</groupId>
        <artifactId>modelmapper</artifactId>
        <version>3.1.0</version>
    </dependency>
    <dependency>
        <groupId>com.fasterxml.jackson.datatype</groupId>
        <artifactId>jackson-datatype-jsr310</artifactId>
    </dependency>
</dependencies>



3. _**java**_:  "SecurityConfig.java"
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
    securedEnabled = true,
    jsr250Enabled = true,
    prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(tokenProvider, customUserDetailsService);
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
            .userDetailsService(customUserDetailsService)
            .passwordEncoder(passwordEncoder());
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .cors()
                .and()
            .csrf()
                .disable()
            .exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)
                .and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
            .authorizeRequests()
                .antMatchers("/",
                    "/favicon.ico",
                    "/**/*.png",
                    "/**/*.gif",
                    "/**/*.svg",
                    "/**/*.jpg",
                    "/**/*.html",
                    "/**/*.css",
                    "/**/*.js")
                    .permitAll()
                .antMatchers("/api/auth/**")
                    .permitAll()
                .antMatchers("/api/user/checkUsernameAvailability", "/api/user/checkEmailAvailability")
                    .permitAll()
                .anyRequest()
                    .authenticated();

        // Add our custom JWT security filter
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}



  **JwtTokenProvider.java**:
@Component
public class JwtTokenProvider {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    @Value("${app.jwtRefreshExpirationInMs}")
    private int jwtRefreshExpirationInMs;

    public String generateToken(UserPrincipal userPrincipal) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String generateRefreshToken(UserPrincipal userPrincipal) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtRefreshExpirationInMs);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public Long getUserIdFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }
}



 4. **AuthController.java**:
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

     Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );

     SecurityContextHolder.getContext().setAuthentication(authentication);

     UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
     
        // Check if account is locked
        if (userPrincipal.getLocked()) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Account is locked!"));
        }

        String jwt = tokenProvider.generateToken(userPrincipal);
        String refreshToken = tokenProvider.generateRefreshToken(userPrincipal);
        
        // Reset login attempts on successful login
        User user = userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
        
        user.setLoginAttempts(0);
        user.setLastLogin(new Date());
        userRepository.save(user);

        return ResponseEntity.ok(new JwtAuthenticationResponse(
                jwt, 
                refreshToken, 
                userPrincipal.getId(), 
                userPrincipal.getUsername(), 
                userPrincipal.getEmail(),
                userPrincipal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        if (!tokenProvider.validateToken(requestRefreshToken)) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Refresh token is invalid!"));
        }

        Long userId = tokenProvider.getUserIdFromJWT(requestRefreshToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

        UserPrincipal userPrincipal = UserPrincipal.create(user);
        String token = tokenProvider.generateToken(userPrincipal);
        String newRefreshToken = tokenProvider.generateRefreshToken(userPrincipal);

        return ResponseEntity.ok(new JwtAuthenticationResponse(
                token, 
                newRefreshToken, 
                userPrincipal.getId(), 
                userPrincipal.getUsername(), 
                userPrincipal.getEmail(),
                userPrincipal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        ));
    }
}



5. **EncryptionConfig.java**:
@Configuration
public class EncryptionConfig {

    @Value("${encryption.key}")
    private String encryptionKey;

    @Bean
    public EncryptionService encryptionService() {
        return new EncryptionService(encryptionKey);
    }
}


**EncryptionService.java**
   @Service
public class EncryptionService {
    private final String algorithm = "AES/GCM/NoPadding";
    private final SecretKeySpec secretKeySpec;
    private final GCMParameterSpec ivSpec;

public EncryptionService(@Value("${encryption.key}") String encryptionKey) {
        try {
            // Ensure the key is 32 bytes (AES-256)
            byte[] keyBytes = Arrays.copyOf(encryptionKey.getBytes(StandardCharsets.UTF_8), 32);
            this.secretKeySpec = new SecretKeySpec(keyBytes, "AES");
            
  // Fixed IV for demonstration (in production, generate random IV for each encryption)
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            this.ivSpec = new GCMParameterSpec(128, iv);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize encryption service", e);
        }
    }

  public String encrypt(String data) {
        if (data == null) return null;
            try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
                   byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }
 public String decrypt(String encryptedData) {
        if (encryptedData == null) return null;
           try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
                 byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}


6.  **BackupService.java**:
@Service
public class BackupService {

    private static final Logger logger = LoggerFactory.getLogger(BackupService.class);

    @Value("${backup.directory}")
    private String backupDirectory;

    @Value("${backup.retention.days:7}")
    private int backupRetentionDays;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private EncryptionService encryptionService;

    @Scheduled(cron = "${backup.cron.expression:0 0 2 * * ?}") // Daily at 2 AM
    public void scheduledBackup() {
        try {
            createBackup();
        } catch (Exception e) {
            logger.error("Scheduled backup failed", e);
        }
    }

    public String createBackup() throws IOException {
        Path backupDir = Paths.get(backupDirectory);
        if (!Files.exists(backupDir)) {
            Files.createDirectories(backupDir);
        }

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String backupFileName = "backup_" + timestamp + ".sql";
        Path backupPath = backupDir.resolve(backupFileName);
        Path encryptedPath = backupDir.resolve(backupFileName + ".enc");

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             BufferedWriter writer = Files.newBufferedWriter(backupPath)) {

            // Get all tables
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet tables = metaData.getTables(null, null, "%", new String[]{"TABLE"});

            while (tables.next()) {
                String tableName = tables.getString("TABLE_NAME");
                writer.write("-- Table: " + tableName);
                writer.newLine();

                // Export table structure
                writer.write("DROP TABLE IF EXISTS " + tableName + ";");
                writer.newLine();

                ResultSet createTable = statement.executeQuery(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='" + tableName + "'");
                if (createTable.next()) {
                    writer.write(createTable.getString("sql") + ";");
                    writer.newLine();
                }

                // Export table data
                writer.write("-- Data for table: " + tableName);
                writer.newLine();

                ResultSet data = statement.executeQuery("SELECT * FROM " + tableName);
                ResultSetMetaData dataMetaData = data.getMetaData();
                int columnCount = dataMetaData.getColumnCount();

                while (data.next()) {
                    writer.write("INSERT INTO " + tableName + " VALUES (");
                    for (int i = 1; i <= columnCount; i++) {
                        if (i > 1) writer.write(", ");
                        String value = data.getString(i);
                        if (value == null) {
                            writer.write("NULL");
                        } else {
                            writer.write("'" + value.replace("'", "''") + "'");
                        }
                    }
                    writer.write(");");
                    writer.newLine();
                }
                writer.newLine();
            }
        }

        // Encrypt the backup file
        String backupContent = new String(Files.readAllBytes(backupPath));
        String encryptedContent = encryptionService.encrypt(backupContent);
        Files.write(encryptedPath, encryptedContent.getBytes());
        
        // Delete the unencrypted backup
        Files.delete(backupPath);

        // Clean up old backups
        cleanupOldBackups();

        return encryptedPath.toString();
    }

    public void restoreBackup(String backupFilePath) throws IOException {
        Path path = Paths.get(backupFilePath);
        if (!Files.exists(path)) {
            throw new FileNotFoundException("Backup file not found: " + backupFilePath);
        }

        // Decrypt the backup
        String encryptedContent = new String(Files.readAllBytes(path));
        String decryptedContent = encryptionService.decrypt(encryptedContent);

        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement()) {
            
            // Split SQL statements
            String[] sqlStatements = decryptedContent.split(";");
            
            // Execute each statement
            for (String sql : sqlStatements) {
                if (!sql.trim().isEmpty()) {
                    statement.execute(sql);
                }
            }
        } catch (SQLException e) {
            throw new IOException("Failed to restore backup", e);
        }
    }

    private void cleanupOldBackups() throws IOException {
        Path backupDir = Paths.get(backupDirectory);
        LocalDate cutoffDate = LocalDate.now().minusDays(backupRetentionDays);

        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(backupDir, "backup_*.enc")) {
            for (Path path : directoryStream) {
                String fileName = path.getFileName().toString();
                String dateStr = fileName.substring(7, 15); // Extract yyyyMMdd
                LocalDate backupDate = LocalDate.parse(dateStr, DateTimeFormatter.BASIC_ISO_DATE);
                
                if (backupDate.isBefore(cutoffDate)) {
                    Files.delete(path);
                    logger.info("Deleted old backup: {}", fileName);
                }
            }
        }
    }
}



7. **Student Entity with Encrypted Fields:**
**Student.java**:
@Entity
@Table(name = "students")
public class Student {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String studentId;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Column(nullable = false)
    @Convert(converter = EncryptionConverter.class)
    private String email;

    @Convert(converter = EncryptionConverter.class)
    private String phone;

    @Convert(converter = EncryptionConverter.class)
    private String address;

    @Column(nullable = false)
    private LocalDate dateOfBirth;

    @Column(nullable = false)
    private LocalDate enrollmentDate;

    @Column(nullable = false)
    private String program;

    // Getters and setters
}


**EncryptionConverter.java**:

@Converter
public class EncryptionConverter implements AttributeConverter<String, String> {

   @Autowired
    private EncryptionService encryptionService;
    @Override
    public String convertToDatabaseColumn(String attribute) {
        return attribute == null ? null : encryptionService.encrypt(attribute);
    }

  @Override
    public String convertToEntityAttribute(String dbData) {
        return dbData == null ? null : encryptionService.decrypt(dbData);
    }
}


8. **Application Properties (application.yml)**:
   **yaml**
   server:
  port: 8080
  servlet:
    context-path: /api

spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/student_management
    username: postgres
    password: yourpassword
    driver-class-name: org.postgresql.Driver
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
    show-sql: true
  liquibase:
    change-log: classpath:db/changelog/db.changelog-master.yaml

app:
  jwtSecret: yourJwtSecretKeyHereAtLeast64CharactersLongForHS512Algorithm
  jwtExpirationInMs: 86400000 # 1 day
  jwtRefreshExpirationInMs: 2592000000 # 30 days

encryption:
  key: your32ByteEncryptionKeyHere123456789012

backup:
  directory: ./backups
  retention.days: 7
  cron.expression: 0 0 2 * * ? # Daily at 2 AM

logging:
  level:
    org.springframework.security: DEBUG
    com.example.studentmanagement: DEBUG



    
