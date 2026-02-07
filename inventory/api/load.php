<?php
header("Content-Type: application/json");
require_once __DIR__ . "/_auth.php";

$expectedApiKey = getenv("INVENTORY_API_KEY") ?: "";
$authorized = false;
if ($expectedApiKey !== "") {
  $receivedApiKey = $_SERVER["HTTP_X_API_KEY"] ?? "";
  if ($receivedApiKey !== "" && hash_equals($expectedApiKey, $receivedApiKey)) {
    $authorized = true;
  }
}
if(!$authorized){
  require_auth_user("viewer");
}

$file = __DIR__ . "/../data/inventory.json";
if (!file_exists($file)) {
  echo json_encode([]);
  exit;
}

$raw = file_get_contents($file);
if ($raw === false) {
  http_response_code(500);
  echo json_encode(["error" => "Could not read data"]);
  exit;
}

$decoded = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) {
  http_response_code(500);
  echo json_encode(["error" => "Stored data is corrupted"]);
  exit;
}

echo json_encode($decoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
