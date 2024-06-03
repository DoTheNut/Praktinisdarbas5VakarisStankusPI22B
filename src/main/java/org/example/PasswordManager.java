package org.example;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;

public class PasswordManager {

    private static final String PASSWORDS_FILE = "passwords.csv";
    private static final String ACCOUNTS_FILE = "accounts.csv";
    private static final String KEY_FILE = "key.bin";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Check if necessary files exist, if not create them
        checkAndCreateFile(PASSWORDS_FILE);
        checkAndCreateFile(ACCOUNTS_FILE);
        checkAndCreateFile(KEY_FILE);

        Scanner scanner = new Scanner(System.in);

        System.out.println("Password Manager");
        System.out.println("1. Register");
        System.out.println("2. Login");

        int choice = scanner.nextInt();
        scanner.nextLine();

        if (choice == 1) {
            register(scanner);
        } else if (choice == 2) {
            login(scanner);
        } else {
            System.out.println("Invalid choice.");
        }
    }

    private static void checkAndCreateFile(String fileName) throws IOException {
        File file = new File(fileName);
        if (!file.exists()) {
            file.createNewFile();
        }
    }

    private static void register(Scanner scanner) throws Exception {
        System.out.println("Register a new account");
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        // Hash the password
        String hashedPassword = hashPassword(password);

        // Save user data
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(ACCOUNTS_FILE, true)))) {
            out.println(username + "," + hashedPassword);
        }

        // Generate and save AES key
        SecretKey key = generateAESKey();
        saveKey(key);

        System.out.println("Registration successful. Please login to continue.");
    }

    private static void login(Scanner scanner) throws Exception {
        System.out.println("Login to your account");
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        if (authenticateUser(username, password)) {
            SecretKey key = loadKey();
            managePasswords(scanner, key);
        } else {
            System.out.println("Invalid username or password.");
        }
    }

    private static boolean authenticateUser(String username, String password) throws Exception {
        try (BufferedReader br = new BufferedReader(new FileReader(ACCOUNTS_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts[0].equals(username) && validatePassword(password, parts[1])) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void managePasswords(Scanner scanner, SecretKey key) throws Exception {
        while (true) {
            System.out.println("Password Management");
            System.out.println("1. Save new password");
            System.out.println("2. Search password");
            System.out.println("3. Update password");
            System.out.println("4. Delete password");
            System.out.println("5. Generate random password");
            System.out.println("6. Exit");

            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    savePassword(scanner, key);
                    break;
                case 2:
                    searchPassword(scanner, key);
                    break;
                case 3:
                    updatePassword(scanner, key);
                    break;
                case 4:
                    deletePassword(scanner, key);
                    break;
                case 5:
                    generateRandomPassword();
                    break;
                case 6:
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    private static void savePassword(Scanner scanner, SecretKey key) throws Exception {
        System.out.print("Enter title: ");
        String title = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        System.out.print("Enter URL/application: ");
        String url = scanner.nextLine();
        System.out.print("Enter comment: ");
        String comment = scanner.nextLine();

        String encryptedPassword = encrypt(password, key);

        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(PASSWORDS_FILE, true)))) {
            out.println(title + "," + encryptedPassword + "," + url + "," + comment);
        }

        System.out.println("Password saved successfully.");
    }

    private static void searchPassword(Scanner scanner, SecretKey key) throws Exception {
        System.out.print("Enter title to search: ");
        String title = scanner.nextLine();

        try (BufferedReader br = new BufferedReader(new FileReader(PASSWORDS_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts[0].equals(title)) {
                    System.out.println("Title: " + parts[0]);
                    System.out.println("Encrypted Password: " + parts[1]);
                    System.out.println("URL/Application: " + parts[2]);
                    System.out.println("Comment: " + parts[3]);
                    System.out.print("Show password? (yes/no): ");
                    String show = scanner.nextLine();
                    if (show.equalsIgnoreCase("yes")) {
                        String decryptedPassword = decrypt(parts[1], key);
                        System.out.println("Password: " + decryptedPassword);
                    }
                    return;
                }
            }
        }

        System.out.println("Password not found.");
    }

    private static void updatePassword(Scanner scanner, SecretKey key) throws Exception {
        System.out.print("Enter title to update: ");
        String title = scanner.nextLine();
        System.out.print("Enter new password: ");
        String newPassword = scanner.nextLine();

        List<String[]> passwordList = new ArrayList<>();
        boolean found = false;

        try (BufferedReader br = new BufferedReader(new FileReader(PASSWORDS_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts[0].equals(title)) {
                    parts[1] = encrypt(newPassword, key);
                    found = true;
                }
                passwordList.add(parts);
            }
        }

        if (found) {
            try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(PASSWORDS_FILE)))) {
                for (String[] parts : passwordList) {
                    out.println(String.join(",", parts));
                }
            }
            System.out.println("Password updated successfully.");
        } else {
            System.out.println("Password not found.");
        }
    }

    private static void deletePassword(Scanner scanner, SecretKey key) throws Exception {
        System.out.print("Enter title to delete: ");
        String title = scanner.nextLine();

        List<String[]> passwordList = new ArrayList<>();
        boolean found = false;

        try (BufferedReader br = new BufferedReader(new FileReader(PASSWORDS_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (!parts[0].equals(title)) {
                    passwordList.add(parts);
                } else {
                    found = true;
                }
            }
        }

        if (found) {
            try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(PASSWORDS_FILE)))) {
                for (String[] parts : passwordList) {
                    out.println(String.join(",", parts));
                }
            }
            System.out.println("Password deleted successfully.");
        } else {
            System.out.println("Password not found.");
        }
    }

    private static void generateRandomPassword() {
        int length = 12;
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        System.out.println("Generated Password: " + sb.toString());
    }

    private static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        byte[] encryptedMessage = new byte[GCM_IV_LENGTH + encryptedData.length];
        System.arraycopy(iv, 0, encryptedMessage, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedData, 0, encryptedMessage, GCM_IV_LENGTH, encryptedData.length);
        return Base64.toBase64String(encryptedMessage);
    }

    private static String decrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        byte[] encryptedMessage = Base64.decode(data);
        byte[] iv = Arrays.copyOfRange(encryptedMessage, 0, GCM_IV_LENGTH);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        byte[] decryptedData = cipher.doFinal(encryptedMessage, GCM_IV_LENGTH, encryptedMessage.length - GCM_IV_LENGTH);
        return new String(decryptedData);
    }

    private static String hashPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        String saltString = Base64.toBase64String(salt);
        byte[] hashedPassword = PBKDF2(password, salt);
        return saltString + ":" + Base64.toBase64String(hashedPassword);
    }

    private static byte[] PBKDF2(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    private static boolean validatePassword(String password, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] parts = storedPassword.split(":");
        byte[] salt = Base64.decode(parts[0]);
        byte[] storedHash = Base64.decode(parts[1]);
        byte[] hash = PBKDF2(password, salt);
        return Arrays.equals(storedHash, hash);
    }

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private static void saveKey(SecretKey key) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(KEY_FILE)) {
            fos.write(key.getEncoded());
        }
    }

    private static SecretKey loadKey() throws IOException {
        byte[] keyBytes = new byte[32];
        try (FileInputStream fis = new FileInputStream(KEY_FILE)) {
            fis.read(keyBytes);
        }
        return new SecretKeySpec(keyBytes, "AES");
    }
}
