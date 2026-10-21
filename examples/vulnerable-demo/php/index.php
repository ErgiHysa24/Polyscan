<?php
$db = new mysqli("localhost", "app", "app", "app");
$name = $_GET["name"];
$result = $db->query("SELECT * FROM users WHERE name = '" . $name . "'"); // SQL injection
echo "Hello " . $_GET["name"];                                           // reflected XSS
eval($_GET["code"]);                                                      // code execution
system("ping " . $_GET["host"]);                                          // command injection
