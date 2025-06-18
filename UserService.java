// UserService.java - Contains multiple privacy compliance issues for testing

package com.example.userservice;

import java.sql.*;
import java.util.*;
import java.util.regex.Pattern;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class UserService {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/userdb";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "password123";
    
    // ISSUE: Hardcoded sensitive data patterns
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$");
    private static final String TEST_EMAIL = "john.doe@example.com";
    private static final String TEST_PHONE = "555-123-4567";
    private static final String TEST_SSN = "123-45-6789";
    
    /**
     * ISSUE: Collect user data without explicit consent mechanism
     */
    public void collectUserData(String email, String phone, String personalId) {
        // Collecting personal data without consent verification
        System.out.println("Collecting user data: " + email);
        
        // ISSUE: Database operation on user data without proper safeguards
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String sql = "INSERT INTO users (email, phone, ssn, created_date) VALUES (?, ?, ?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, email);
            stmt.setString(2, phone);
            stmt.setString(3, personalId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * ISSUE: Cookie tracking without consent
     */
    public void setTrackingCookies(HttpServletResponse response) {
        // Setting tracking cookies without consent check
        Cookie analyticsCookie = new Cookie("analytics_id", UUID.randomUUID().toString());
        analyticsookie.setMaxAge(365 * 24 * 60 * 60); // 1 year
        response.addCookie(analyticsookie);
        
        Cookie marketingCookie = new Cookie("marketing_pref", "all");
        marketingCookie.setMaxAge(365 * 24 * 60 * 60);
        response.addCookie(marketingCookie);
    }
    
    /**
     * ISSUE: Newsletter signup without explicit opt-in
     */
    public void subscribeToNewsletter(String email) {
        // Adding user to marketing email list without explicit consent
        System.out.println("Adding " + email + " to promotional email list");
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String sql = "INSERT INTO newsletter_subscribers (email, subscribed_date) VALUES (?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, email);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * ISSUE: Indefinite data retention
     */
    public void storeUserDataPermanently(UserData userData) {
        // Storing user data permanently without retention policy
        System.out.println("Storing user data forever in permanent storage");
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String sql = "INSERT INTO permanent_user_data (user_id, email, phone, ip_address, " +
                        "credit_card, passport_number) VALUES (?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, userData.getUserId());
            stmt.setString(2, userData.getEmail());
            stmt.setString(3, userData.getPhone());
            stmt.setString(4, userData.getIpAddress());
            stmt.setString(5, userData.getCreditCard());
            stmt.setString(6, userData.getPassportNumber());
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * ISSUE: Transfer data to third party without safeguards
     */
    public void shareDataWithPartners(String userId) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            // Retrieving user data
            String selectSql = "SELECT * FROM users WHERE user_id = ?";
            PreparedStatement selectStmt = conn.prepareStatement(selectSql);
            selectStmt.setString(1, userId);
            ResultSet rs = selectStmt.executeQuery();
            
            if (rs.next()) {
                String email = rs.getString("email");
                String phone = rs.getString("phone");
                String personalData = rs.getString("personal_data");
                
                // ISSUE: Transfer user data to external third party
                sendDataToExternalPartner(email, phone, personalData);
                System.out.println("User data transferred to third party marketing partner");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    private void sendDataToExternalPartner(String email, String phone, String data) {
        // Simulated external data transfer
        System.out.println("Sending data outside our organization to marketing partner");
    }
    
    /**
     * ISSUE: No proper data access mechanism for users
     */
    public void getUserData(String userId) {
        // Limited data access - doesn't provide complete user data access
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String sql = "SELECT email, phone FROM users WHERE user_id = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();
            
            // Only partial data access provided
            System.out.println("Providing limited user data access");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * ISSUE: No proper data deletion mechanism
     */
    public void deleteUserAccount(String userId) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            // Only soft delete - data retained indefinitely
            String sql = "UPDATE users SET status = 'deleted' WHERE user_id = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, userId);
            stmt.executeUpdate();
            
            System.out.println("User account marked as deleted but data retained permanently");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * ISSUE: Logging sensitive information
     */
    public void processPayment(String creditCardNumber, String email, String customerId) {
        // Logging sensitive payment information
        System.out.println("Processing payment for card: " + creditCardNumber);
        System.out.println("Customer email: " + email);
        System.out.println("Customer ID: " + customerId);
        
        // Store in logs permanently
        logPaymentInfo("Payment processed for " + creditCardNumber + " customer " + email);
    }
    
    private void logPaymentInfo(String logMessage) {
        // Logs stored indefinitely with sensitive data
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String sql = "INSERT INTO audit_logs (log_message, created_date) VALUES (?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, logMessage);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * ISSUE: IP address tracking without consent
     */
    public void trackUserActivity(String ipAddress, String userAgent, String userId) {
        System.out.println("Tracking user activity from IP: " + ipAddress);
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            String sql = "INSERT INTO user_tracking (user_id, ip_address, user_agent, " +
                        "tracking_date) VALUES (?, ?, ?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, userId);
            stmt.setString(2, ipAddress);
            stmt.setString(3, userAgent);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// Additional class with more issues
class AnalyticsService {
    
    /**
     * ISSUE: Analytics tracking without consent
     */
    public void trackUserBehavior(String userId, String email, String activity) {
        // Track user behavior without consent
        System.out.println("Tracking user behavior for analytics purposes");
        
        Map<String, String> analyticsData = new HashMap<>();
        analyticsData.put("user_id", userId);
        analyticsData.put("email", email);
        analyticsData.put("activity", activity);
        analyticsData.put("timestamp", String.valueOf(System.currentTimeMillis()));
        
        // Send to analytics service
        sendToAnalyticsService(analyticsData);
    }
    
    private void sendToAnalyticsService(Map<String, String> data) {
        System.out.println("Sending user data to external analytics service");
    }
    
    /**
     * ISSUE: Creating user profiles without consent
     */
    public void createUserProfile(String email, String phone, String interests, String location) {
        System.out.println("Creating comprehensive user profile for targeted advertising");
        
        UserProfile profile = new UserProfile();
        profile.setEmail(email);
        profile.setPhone(phone);
        profile.setInterests(interests);
        profile.setLocation(location);
        profile.setCreatedDate(new Date());
        
        // Store profile indefinitely
        storeProfilePermanently(profile);
    }
    
    private void storeProfilePermanently(UserProfile profile) {
        System.out.println("Storing user profile data permanently for marketing purposes");
    }
}

// Supporting classes
class UserData {
    private String userId;
    private String email;
    private String phone;
    private String ipAddress;
    private String creditCard;
    private String passportNumber;
    
    // Getters and setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    
    public String getCreditCard() { return creditCard; }
    public void setCreditCard(String creditCard) { this.creditCard = creditCard; }
    
    public String getPassportNumber() { return passportNumber; }
    public void setPassportNumber(String passportNumber) { this.passportNumber = passportNumber; }
}

class UserProfile {
    private String email;
    private String phone;
    private String interests;
    private String location;
    private Date createdDate;
    
    // Getters and setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    
    public String getInterests() { return interests; }
    public void setInterests(String interests) { this.interests = interests; }
    
    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
    
    public Date getCreatedDate() { return createdDate; }
    public void setCreatedDate(Date createdDate) { this.createdDate = createdDate; }
}