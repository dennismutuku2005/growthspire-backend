<?php
// api/applications.php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Include database connection
require_once '../includes/db.php';

// Get the request method
$method = $_SERVER['REQUEST_METHOD'];

// Helper function to send JSON response
function sendResponse($status, $message, $data = null) {
    http_response_code($status);
    echo json_encode([
        'status' => $status,
        'message' => $message,
        'data' => $data,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    exit();
}

// Helper function to sanitize input
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Helper function to validate email
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Helper function to validate URL
function validateURL($url) {
    if (empty($url)) return true;
    return filter_var($url, FILTER_VALIDATE_URL);
}

// Helper function to validate phone number (basic validation)
function validatePhone($phone) {
    // Remove all non-digit characters
    $phone = preg_replace('/[^0-9]/', '', $phone);
    return strlen($phone) >= 8 && strlen($phone) <= 15;
}

// GET: Retrieve applications (with optional filtering)
if ($method === 'GET') {
    try {
        // Check if we're getting a specific application
        if (isset($_GET['id'])) {
            $id = sanitizeInput($_GET['id']);
            $stmt = $db->prepare("SELECT * FROM applications WHERE id = :id");
            $stmt->execute(['id' => $id]);
            $application = $stmt->fetch();
            
            if ($application) {
                // Mask sensitive information for security
                unset($application['password_hash']); // Just in case
                sendResponse(200, 'Application retrieved successfully', $application);
            } else {
                sendResponse(404, 'Application not found');
            }
        }
        
        // Check if we're getting applications by type
        elseif (isset($_GET['type'])) {
            $type = sanitizeInput($_GET['type']);
            $validTypes = ['startup', 'sponsor'];
            
            if (!in_array($type, $validTypes)) {
                sendResponse(400, 'Invalid application type');
            }
            
            $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
            $limit = isset($_GET['limit']) ? min(max(1, intval($_GET['limit'])), 100) : 20;
            $offset = ($page - 1) * $limit;
            
            // Get total count
            $countStmt = $db->prepare("SELECT COUNT(*) as total FROM applications WHERE application_type = :type");
            $countStmt->execute(['type' => $type]);
            $total = $countStmt->fetch()['total'];
            
            // Get applications with pagination
            $stmt = $db->prepare("
                SELECT * FROM applications 
                WHERE application_type = :type 
                ORDER BY created_at DESC 
                LIMIT :limit OFFSET :offset
            ");
            $stmt->bindValue(':type', $type, PDO::PARAM_STR);
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            
            $applications = $stmt->fetchAll();
            
            // Remove sensitive data
            foreach ($applications as &$app) {
                unset($app['password_hash']);
            }
            
            sendResponse(200, 'Applications retrieved successfully', [
                'applications' => $applications,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                    'pages' => ceil($total / $limit)
                ]
            ]);
        }
        
        // Check if we're getting applications by status
        elseif (isset($_GET['status'])) {
            $status = sanitizeInput($_GET['status']);
            $validStatuses = ['pending', 'under_review', 'interview', 'accepted', 'rejected'];
            
            if (!in_array($status, $validStatuses)) {
                sendResponse(400, 'Invalid status');
            }
            
            $stmt = $db->prepare("SELECT * FROM applications WHERE status = :status ORDER BY created_at DESC");
            $stmt->execute(['status' => $status]);
            $applications = $stmt->fetchAll();
            
            // Remove sensitive data
            foreach ($applications as &$app) {
                unset($app['password_hash']);
            }
            
            sendResponse(200, 'Applications retrieved successfully', $applications);
        }
        
        // Get all applications (with pagination for admin)
        else {
            // Check for admin authentication (you can implement JWT or session auth)
            $isAdmin = false; // Set to true if authenticated as admin
            
            if (!$isAdmin) {
                sendResponse(401, 'Unauthorized - Admin access required');
            }
            
            $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
            $limit = isset($_GET['limit']) ? min(max(1, intval($_GET['limit'])), 100) : 20;
            $offset = ($page - 1) * $limit;
            
            // Get total count
            $countStmt = $db->prepare("SELECT COUNT(*) as total FROM applications");
            $countStmt->execute();
            $total = $countStmt->fetch()['total'];
            
            // Get all applications
            $stmt = $db->prepare("
                SELECT * FROM applications 
                ORDER BY created_at DESC 
                LIMIT :limit OFFSET :offset
            ");
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            
            $applications = $stmt->fetchAll();
            
            // Remove sensitive data
            foreach ($applications as &$app) {
                unset($app['password_hash']);
            }
            
            sendResponse(200, 'Applications retrieved successfully', [
                'applications' => $applications,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                    'pages' => ceil($total / $limit)
                ]
            ]);
        }
        
    } catch (Exception $e) {
        error_log("GET Error: " . $e->getMessage());
        sendResponse(500, 'Failed to retrieve applications');
    }
}

// POST: Create a new application (for both startup and sponsor)
elseif ($method === 'POST') {
    try {
        // Get JSON input
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            sendResponse(400, 'Invalid JSON input');
        }
        
        // Validate required fields
        $requiredFields = [
            'application_type', 'full_name', 'email', 'phone', 
            'company_name', 'message'
        ];
        
        foreach ($requiredFields as $field) {
            if (empty($input[$field])) {
                sendResponse(400, "Missing required field: $field");
            }
        }
        
        // Validate application type
        $validTypes = ['startup', 'sponsor'];
        if (!in_array($input['application_type'], $validTypes)) {
            sendResponse(400, 'Invalid application type');
        }
        
        // Validate email
        if (!validateEmail($input['email'])) {
            sendResponse(400, 'Invalid email address');
        }
        
        // Validate phone
        if (!validatePhone($input['phone'])) {
            sendResponse(400, 'Invalid phone number');
        }
        
        // Validate URLs if provided
        if (!empty($input['website_url']) && !validateURL($input['website_url'])) {
            sendResponse(400, 'Invalid website URL');
        }
        
        if (!empty($input['linkedin_profile']) && !validateURL($input['linkedin_profile'])) {
            sendResponse(400, 'Invalid LinkedIn profile URL');
        }
        
        if (!empty($input['pitch_deck_url']) && !validateURL($input['pitch_deck_url'])) {
            sendResponse(400, 'Invalid pitch deck URL');
        }
        
        // Prepare data based on application type
        $data = [
            'application_type' => sanitizeInput($input['application_type']),
            'full_name' => sanitizeInput($input['full_name']),
            'email' => sanitizeInput($input['email']),
            'phone' => sanitizeInput($input['phone']),
            'company_name' => sanitizeInput($input['company_name']),
            'message' => sanitizeInput($input['message']),
            'linkedin_profile' => !empty($input['linkedin_profile']) ? sanitizeInput($input['linkedin_profile']) : null,
            'website_url' => !empty($input['website_url']) ? sanitizeInput($input['website_url']) : null,
        ];
        
        // Handle startup-specific fields
        if ($input['application_type'] === 'startup') {
            $startupFields = [
                'startup_stage' => sanitizeInput($input['startup_stage'] ?? ''),
                'industry' => sanitizeInput($input['industry'] ?? ''),
                'funding_needed_range' => sanitizeInput($input['funding_needed_range'] ?? ''),
                'team_size' => sanitizeInput($input['team_size'] ?? ''),
                'pitch_deck_url' => !empty($input['pitch_deck_url']) ? sanitizeInput($input['pitch_deck_url']) : null,
            ];
            
            $data = array_merge($data, $startupFields);
        }
        
        // Handle sponsor-specific fields
        if ($input['application_type'] === 'sponsor') {
            $sponsorFields = [
                'investor_type' => sanitizeInput($input['investor_type'] ?? ''),
                'investment_range' => sanitizeInput($input['investment_range'] ?? ''),
                'focus_areas' => sanitizeInput($input['focus_areas'] ?? ''),
            ];
            
            $data = array_merge($data, $sponsorFields);
        }
        
        // Check if email already has a pending application
        $checkStmt = $db->prepare("
            SELECT id FROM applications 
            WHERE email = :email AND status = 'pending' 
            AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        $checkStmt->execute(['email' => $data['email']]);
        
        if ($checkStmt->fetch()) {
            sendResponse(400, 'You already have a pending application. Please wait 30 days before submitting another.');
        }
        
        // Insert into database
        $columns = implode(', ', array_keys($data));
        $placeholders = ':' . implode(', :', array_keys($data));
        
        $sql = "INSERT INTO applications ($columns) VALUES ($placeholders)";
        $stmt = $db->prepare($sql);
        
        if ($stmt->execute($data)) {
            $applicationId = $db->lastInsertId();
            
            // Get the created application
            $stmt = $db->prepare("SELECT * FROM applications WHERE id = :id");
            $stmt->execute(['id' => $applicationId]);
            $newApplication = $stmt->fetch();
            
            // Remove sensitive data
            unset($newApplication['password_hash']);
            
            // Send notification email (optional)
            sendNotificationEmail($newApplication);
            
            sendResponse(201, 'Application submitted successfully', $newApplication);
        } else {
            sendResponse(500, 'Failed to submit application');
        }
        
    } catch (Exception $e) {
        error_log("POST Error: " . $e->getMessage());
        sendResponse(500, 'Failed to submit application');
    }
}

// PUT: Update application status (for admin)
elseif ($method === 'PUT') {
    try {
        // Check admin authentication
        $isAdmin = false; // Set to true if authenticated as admin
        
        if (!$isAdmin) {
            sendResponse(401, 'Unauthorized - Admin access required');
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['id'])) {
            sendResponse(400, 'Application ID is required');
        }
        
        $id = sanitizeInput($input['id']);
        
        // Check if application exists
        $checkStmt = $db->prepare("SELECT id FROM applications WHERE id = :id");
        $checkStmt->execute(['id' => $id]);
        
        if (!$checkStmt->fetch()) {
            sendResponse(404, 'Application not found');
        }
        
        // Prepare update data
        $updates = [];
        $updateData = ['id' => $id];
        
        if (isset($input['status'])) {
            $validStatuses = ['pending', 'under_review', 'interview', 'accepted', 'rejected'];
            if (!in_array($input['status'], $validStatuses)) {
                sendResponse(400, 'Invalid status');
            }
            $updates[] = 'status = :status';
            $updateData['status'] = sanitizeInput($input['status']);
        }
        
        if (isset($input['reviewer_notes'])) {
            $updates[] = 'reviewer_notes = :reviewer_notes';
            $updateData['reviewer_notes'] = sanitizeInput($input['reviewer_notes']);
        }
        
        if (empty($updates)) {
            sendResponse(400, 'No fields to update');
        }
        
        // Add updated_at timestamp
        $updates[] = 'updated_at = NOW()';
        
        $sql = "UPDATE applications SET " . implode(', ', $updates) . " WHERE id = :id";
        $stmt = $db->prepare($sql);
        
        if ($stmt->execute($updateData)) {
            // Get updated application
            $stmt = $db->prepare("SELECT * FROM applications WHERE id = :id");
            $stmt->execute(['id' => $id]);
            $updatedApplication = $stmt->fetch();
            
            // Remove sensitive data
            unset($updatedApplication['password_hash']);
            
            sendResponse(200, 'Application updated successfully', $updatedApplication);
        } else {
            sendResponse(500, 'Failed to update application');
        }
        
    } catch (Exception $e) {
        error_log("PUT Error: " . $e->getMessage());
        sendResponse(500, 'Failed to update application');
    }
}

// DELETE: Delete application (for admin)
elseif ($method === 'DELETE') {
    try {
        // Check admin authentication
        $isAdmin = false; // Set to true if authenticated as admin
        
        if (!$isAdmin) {
            sendResponse(401, 'Unauthorized - Admin access required');
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input || !isset($input['id'])) {
            sendResponse(400, 'Application ID is required');
        }
        
        $id = sanitizeInput($input['id']);
        
        // Check if application exists
        $checkStmt = $db->prepare("SELECT id FROM applications WHERE id = :id");
        $checkStmt->execute(['id' => $id]);
        
        if (!$checkStmt->fetch()) {
            sendResponse(404, 'Application not found');
        }
        
        // Soft delete (update status to deleted) or hard delete
        // For GDPR compliance, you might want to anonymize instead
        $stmt = $db->prepare("DELETE FROM applications WHERE id = :id");
        
        if ($stmt->execute(['id' => $id])) {
            sendResponse(200, 'Application deleted successfully');
        } else {
            sendResponse(500, 'Failed to delete application');
        }
        
    } catch (Exception $e) {
        error_log("DELETE Error: " . $e->getMessage());
        sendResponse(500, 'Failed to delete application');
    }
}

// Method not allowed
else {
    sendResponse(405, 'Method not allowed');
}

// Helper function to send notification email (optional)
function sendNotificationEmail($application) {
    try {
        // Email to applicant
        $toApplicant = $application['email'];
        $subject = "GrowthSpire Application Received";
        
        $message = "Dear " . $application['full_name'] . ",\n\n";
        $message .= "Thank you for submitting your " . $application['application_type'] . " application to GrowthSpire.\n\n";
        $message .= "We have received your application and our team will review it within 5-7 business days.\n\n";
        $message .= "Application Details:\n";
        $message .= "- Type: " . ucfirst($application['application_type']) . "\n";
        $message .= "- Company: " . $application['company_name'] . "\n";
        $message .= "- Reference ID: " . $application['id'] . "\n\n";
        $message .= "If you have any questions, please don't hesitate to contact us.\n\n";
        $message .= "Best regards,\n";
        $message .= "The GrowthSpire Team\n";
        $message .= "https://growthspire.co.ke";
        
        // Email headers
        $headers = "From: no-reply@growthspire.co.ke\r\n";
        $headers .= "Reply-To: info@growthspire.co.ke\r\n";
        $headers .= "X-Mailer: PHP/" . phpversion();
        
        // Send email (you can enable this in production)
        // mail($toApplicant, $subject, $message, $headers);
        
        // Also send notification to admin
        $toAdmin = "admin@growthspire.co.ke";
        $adminSubject = "New GrowthSpire Application: " . $application['application_type'];
        
        $adminMessage = "A new " . $application['application_type'] . " application has been submitted:\n\n";
        $adminMessage .= "Name: " . $application['full_name'] . "\n";
        $adminMessage .= "Email: " . $application['email'] . "\n";
        $adminMessage .= "Phone: " . $application['phone'] . "\n";
        $adminMessage .= "Company: " . $application['company_name'] . "\n";
        $adminMessage .= "Application ID: " . $application['id'] . "\n\n";
        $adminMessage .= "Login to the admin panel to review: https://admin.growthspire.co.ke";
        
        // mail($toAdmin, $adminSubject, $adminMessage, $headers);
        
        return true;
    } catch (Exception $e) {
        error_log("Email Error: " . $e->getMessage());
        return false;
    }
}
?>