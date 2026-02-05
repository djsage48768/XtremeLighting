<?php
header("Content-Type: application/json");

$expectedApiKey = getenv("INVENTORY_API_KEY") ?: "";
if ($expectedApiKey !== "") {
  $receivedApiKey = $_SERVER["HTTP_X_API_KEY"] ?? "";
  if (!hash_equals($expectedApiKey, $receivedApiKey)) {
    http_response_code(401);
    echo json_encode(["error" => "Unauthorized"]);
    exit;
  }
}

$raw = file_get_contents("php://input");
if ($raw === false || trim($raw) === "") {
  http_response_code(400);
  echo json_encode(["error" => "No data received"]);
  exit;
}

$decoded = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
  http_response_code(400);
  echo json_encode(["error" => "Invalid JSON payload"]);
  exit;
}

$payload = json_encode($decoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
if ($payload === false) {
  http_response_code(500);
  echo json_encode(["error" => "Could not encode payload"]);
  exit;
}

$file = __DIR__ . "/../data/inventory.json";
$dir = dirname($file);
if (!is_dir($dir) && !mkdir($dir, 0775, true)) {
  http_response_code(500);
  echo json_encode(["error" => "Data directory is unavailable"]);
  exit;
}

$tmpFile = $file . ".tmp." . bin2hex(random_bytes(6));
if (file_put_contents($tmpFile, $payload, LOCK_EX) === false) {
  http_response_code(500);
  echo json_encode(["error" => "Could not write temp data"]);
  exit;
}

if (!rename($tmpFile, $file)) {
  @unlink($tmpFile);
  http_response_code(500);
  echo json_encode(["error" => "Could not save data"]);
  exit;
}

http_response_code(200);
echo json_encode(["status" => "ok"]);
