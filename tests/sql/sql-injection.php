<?php
function concat($db, $name) {
    // ruleid: polyscan-sql-php
    $db->query("SELECT * FROM users WHERE name = '" . $name . "'");
}

function interpolated($db, $name) {
    // ruleid: polyscan-sql-php
    mysqli_query($db, "SELECT * FROM users WHERE name = '$name'");
}

function sprintfCall($db, $name) {
    // ruleid: polyscan-sql-php
    $db->exec(sprintf("DELETE FROM users WHERE name = '%s'", $name));
}

function viaVariable($db, $name) {
    $q = "SELECT * FROM users WHERE name = '" . $name . "'";
    // ruleid: polyscan-sql-php
    $db->query($q);
}

function prepared($db, $name) {
    // ok: polyscan-sql-php
    $stmt = $db->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->execute([$name]);
}

function constantOnly($db) {
    // ok: polyscan-sql-php
    $db->query("SELECT * FROM users");
}

function notSql($a, $b) {
    // ok: polyscan-sql-php
    echo "total: " . $a . $b;
}
