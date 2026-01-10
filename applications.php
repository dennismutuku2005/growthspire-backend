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
require_once './includes/db.php';

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

// Helper function to format phone number for WhatsApp
function formatPhoneForWhatsApp($phone) {
    // Remove all non-digit characters
    $phone = preg_replace('/[^0-9]/', '', $phone);
    
    // If number starts with 0, replace with 254
    if (substr($phone, 0, 1) === '0') {
        $phone = '254' . substr($phone, 1);
    }
    
    // If number is 9 digits, assume it's Kenyan and add 254
    if (strlen($phone) === 9) {
        $phone = '254' . $phone;
    }
    
    return $phone;
}

// Helper function to send WhatsApp request
function sendWhatsAppRequest($phone, $applicationData) {
    try {
        // Format the phone number
        $formattedPhone = formatPhoneForWhatsApp($phone);
        
        // Prepare message
        $appType = $applicationData['application_type'] === 'startup' ? 'Startup' : 'Sponsor';
        $message = "🚀 *GrowthSpire Application Received*\n\n";
        $message .= "Hello " . $applicationData['full_name'] . ",\n\n";
        $message .= "Thank you for submitting your " . $appType . " application!\n\n";
        $message .= "*Application Details:*\n";
        $message .= "• Type: " . $appType . "\n";
        $message .= "• Company: " . $applicationData['company_name'] . "\n";
        $message .= "• Reference: " . $applicationData['id'] . "\n\n";
        $message .= "Our team will review your application within 5-7 business days.\n\n";
        $message .= "Best regards,\n";
        $message .= "GrowthSpire Team 🌟";
        
        // Prepare data for WhatsApp API
        $whatsappData = [
            'number' => $formattedPhone,
            'message' => $message
        ];
        
        // Log for debugging
        error_log("Sending WhatsApp to: {$formattedPhone}, App ID: {$applicationData['id']}");
        
        // Send to WhatsApp API
        $ch = curl_init('http://whatsapp.quickzingo.com/send');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($whatsappData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json'
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3); // 3 second timeout
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        error_log("WhatsApp API Response - HTTP: {$httpCode}");
        
        return true;
    } catch (Exception $e) {
        error_log("WhatsApp Error: " . $e->getMessage());
        return false;
    }
}

// GET: Retrieve applications
if ($method === 'GET') {
    try {
        // Check if we're getting a specific application
        if (isset($_GET['id'])) {
            $id = sanitizeInput($_GET['id']);
            $stmt = $db->prepare("SELECT * FROM applications WHERE id = :id");
            $stmt->execute(['id' => $id]);
            $application = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($application) {
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
            $total = $countStmt->fetchColumn();
            
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
            
            $applications = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
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
            $applications = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            sendResponse(200, 'Applications retrieved successfully', $applications);
        }
        
        // Get all applications (with pagination for admin)
        else {
            // Check for admin authentication
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
            $total = $countStmt->fetchColumn();
            
            // Get all applications
            $stmt = $db->prepare("
                SELECT * FROM applications 
                ORDER BY created_at DESC 
                LIMIT :limit OFFSET :offset
            ");
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            
            $applications = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
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

// POST: Create a new application
elseif ($method === 'POST') {
    // Store phone number early for WhatsApp
    $phoneForWhatsApp = null;
    $applicationDataForWhatsApp = null;
    
    try {
        // Get JSON input
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!$input) {
            sendResponse(400, 'Invalid JSON input');
        }
        
        // Store phone for WhatsApp (early storage)
        if (isset($input['phone'])) {
            $phoneForWhatsApp = $input['phone'];
        }
        
        // Validate required fields
        $requiredFields = ['application_type', 'full_name', 'email', 'phone', 'company_name', 'message'];
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
        
        // Generate UUID for the application
        $uuid = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
        
        // Prepare application data for response
        $applicationData = [
            'id' => $uuid,
            'application_type' => sanitizeInput($input['application_type']),
            'full_name' => sanitizeInput($input['full_name']),
            'email' => sanitizeInput($input['email']),
            'phone' => sanitizeInput($input['phone']),
            'company_name' => sanitizeInput($input['company_name']),
            'website_url' => !empty($input['website_url']) ? sanitizeInput($input['website_url']) : null,
            'linkedin_profile' => !empty($input['linkedin_profile']) ? sanitizeInput($input['linkedin_profile']) : null,
            'message' => sanitizeInput($input['message']),
            'status' => 'pending',
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s')
        ];
        
        // Add startup-specific fields
        if ($input['application_type'] === 'startup') {
            $applicationData['startup_stage'] = !empty($input['startup_stage']) ? sanitizeInput($input['startup_stage']) : null;
            $applicationData['industry'] = !empty($input['industry']) ? sanitizeInput($input['industry']) : null;
            $applicationData['funding_needed_range'] = !empty($input['funding_needed_range']) ? sanitizeInput($input['funding_needed_range']) : null;
            $applicationData['team_size'] = !empty($input['team_size']) ? sanitizeInput($input['team_size']) : null;
            $applicationData['pitch_deck_url'] = !empty($input['pitch_deck_url']) ? sanitizeInput($input['pitch_deck_url']) : null;
        }
        
        // Add sponsor-specific fields
        if ($input['application_type'] === 'sponsor') {
            $applicationData['investor_type'] = !empty($input['investor_type']) ? sanitizeInput($input['investor_type']) : null;
            $applicationData['investment_range'] = !empty($input['investment_range']) ? sanitizeInput($input['investment_range']) : null;
            $applicationData['focus_areas'] = !empty($input['focus_areas']) ? sanitizeInput($input['focus_areas']) : null;
        }
        
        // Store complete application data for WhatsApp
        $applicationDataForWhatsApp = $applicationData;
        
        // Check if email already has a pending application
        $checkStmt = $db->prepare("
            SELECT id FROM applications 
            WHERE email = :email AND status = 'pending' 
            AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        $checkStmt->execute(['email' => $applicationData['email']]);
        
        if ($checkStmt->fetch()) {
            sendResponse(400, 'You already have a pending application. Please wait 30 days before submitting another.');
        }
        
        // Prepare SQL statement
        $sql = "INSERT INTO applications (
            id, application_type, full_name, email, phone, company_name,
            website_url, linkedin_profile, message, status,
            startup_stage, industry, funding_needed_range, team_size, pitch_deck_url,
            investor_type, investment_range, focus_areas,
            created_at, updated_at
        ) VALUES (
            :id, :application_type, :full_name, :email, :phone, :company_name,
            :website_url, :linkedin_profile, :message, :status,
            :startup_stage, :industry, :funding_needed_range, :team_size, :pitch_deck_url,
            :investor_type, :investment_range, :focus_areas,
            :created_at, :updated_at
        )";
        
        $stmt = $db->prepare($sql);
        
        // Execute the insert
        $success = $stmt->execute([
            ':id' => $applicationData['id'],
            ':application_type' => $applicationData['application_type'],
            ':full_name' => $applicationData['full_name'],
            ':email' => $applicationData['email'],
            ':phone' => $applicationData['phone'],
            ':company_name' => $applicationData['company_name'],
            ':website_url' => $applicationData['website_url'],
            ':linkedin_profile' => $applicationData['linkedin_profile'],
            ':message' => $applicationData['message'],
            ':status' => $applicationData['status'],
            ':startup_stage' => $applicationData['startup_stage'] ?? null,
            ':industry' => $applicationData['industry'] ?? null,
            ':funding_needed_range' => $applicationData['funding_needed_range'] ?? null,
            ':team_size' => $applicationData['team_size'] ?? null,
            ':pitch_deck_url' => $applicationData['pitch_deck_url'] ?? null,
            ':investor_type' => $applicationData['investor_type'] ?? null,
            ':investment_range' => $applicationData['investment_range'] ?? null,
            ':focus_areas' => $applicationData['focus_areas'] ?? null,
            ':created_at' => $applicationData['created_at'],
            ':updated_at' => $applicationData['updated_at']
        ]);
        
        if ($success) {
            // Database insert successful - send response FIRST
            sendResponse(201, 'Application submitted successfully', $applicationData);
            
            // AFTER sending response, send WhatsApp notification
            // This happens in background and doesn't block the response
            if ($phoneForWhatsApp && $applicationDataForWhatsApp) {
                try {
                    // Send WhatsApp notification
                    sendWhatsAppRequest($phoneForWhatsApp, $applicationDataForWhatsApp);
                } catch (Exception $e) {
                    // Log but don't throw error - WhatsApp failure shouldn't affect application
                    error_log("Background WhatsApp failed: " . $e->getMessage());
                }
            }
            
            // Exit after sending response and starting background process
            exit();
            
        } else {
            $errorInfo = $stmt->errorInfo();
            error_log("Database insert failed: " . json_encode($errorInfo));
            sendResponse(500, 'Failed to save application to database');
        }
        
    } catch (Exception $e) {
        error_log("POST Error: " . $e->getMessage());
        sendResponse(500, 'Server error: ' . $e->getMessage());
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
            $updatedApplication = $stmt->fetch(PDO::FETCH_ASSOC);
            
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
?>