<?php
/**
 * Whois
 * 
 * @version 1
 * @author NL neor.digital
 */

// get Whois data
function getWhoisData($ip, $service="whois.iana.org") {
    // Open a socket connection to the WHOIS server
    $connection = fsockopen($service, 43);
    if (!$connection) {
        return "Connection failed!";
    }
    // Send the IP to the WHOIS server
    fwrite($connection, $ip . "\r\n");
    // Retrieve the WHOIS data
    $data = [];
    while (!feof($connection)) {
        $data[] = fgets($connection, 10000);
    }
    // Close the connection
    fclose($connection);
    
    foreach($data as $i => $str) {
        preg_match("/^(?:%|#|Terms)/", $str, $match);  // erase comments, sorry
        if ( isset($match[0]) ) {
            unset($data[$i]);
        }
        if ( empty(trim($str)) ) unset($data[$i]); // erase empty strings

        preg_match("/^whois:\s*(.*)/", $str, $match);  // find another Service
        if ( isset($match[1]) ) {
            // try another Service
            $result = getWhoisData($ip, $match[1]); // recursive Fetch
            $service = $result['service'];
            $data = $result['data'];
            break;
        }
    }
    
    if ( is_array($data) ) {
        $data = (!empty($data)) ? implode("", $data) : "No data\n";
    }

    return [
        "service" => $service, 
        "data" => $data
    ];
}

function isValidIP($str) {
    return filter_var($str, FILTER_VALIDATE_IP) !== false;
}


echo "Whois IP\Domain \n\n";

$ip = isset($argv[1]) ? $argv[1] : '';

if (empty($ip)) {
    die("Usage:  php whois.php <IP> \n\n");
}

echo isValidIP($ip) ? "IP: " : "Domain: ";
echo $ip ."\n\n";

$result = getWhoisData($ip);
echo "Service: ". $result['service'] ."\n\n". $result['data'] ."\n\n";
