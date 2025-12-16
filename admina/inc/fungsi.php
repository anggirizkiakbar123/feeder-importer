<?php
session_start();

function parse_path(): array
{
    $path = [
        'base'       => '',
        'call'       => '',
        'call_parts' => [],
        'query'      => '',
        'query_vars' => []
    ];

    if (!isset($_SERVER['REQUEST_URI'], $_SERVER['SCRIPT_NAME'])) {
        return $path;
    }

    $request_path = explode('?', $_SERVER['REQUEST_URI'], 2);

    $path['base'] = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');

    $call = urldecode($request_path[0]);
    $call = ltrim(substr($call, strlen($path['base'])), '/');

    if ($call === basename($_SERVER['PHP_SELF'])) {
        $call = '';
    }

    $path['call'] = $call;
    $path['call_parts'] = $call !== '' ? explode('/', $call) : [];

    if (isset($request_path[1]) && $request_path[1] !== '') {
        $path['query'] = urldecode($request_path[1]);
        parse_str($path['query'], $path['query_vars']);
    }

    return $path;
}

$path = parse_path();

$path_url  = $path['call_parts'][1] ?? '';
$path_act  = $path['call_parts'][2] ?? '';
$path_id   = $path['call_parts'][3] ?? '';
$path_four = $path['call_parts'][4] ?? '';
$path_five = $path['call_parts'][5] ?? '';

/* =========================
   SESSION CHECK
========================= */
if (!isset($_SESSION['level'])) {
    die('Unauthorized access');
}

/* =========================
   ROLE & PERMISSION
========================= */
$role_user = [];
$role_act  = [];

/* READ MENU ROLE */
$stmt = $db->prepare("
    SELECT sys_menu.url
    FROM sys_menu
    INNER JOIN sys_menu_role 
        ON sys_menu.id = sys_menu_role.id_menu
    WHERE sys_menu_role.group_id = ?
      AND sys_menu_role.read_act = ?
");
$stmt->execute([$_SESSION['level'], 'Y']);

while ($role = $stmt->fetch(PDO::FETCH_OBJ)) {
    $role_user[] = $role->url;
}

/* CRUD PERMISSION */
$stmt = $db->prepare("
    SELECT read_act, insert_act, update_act, delete_act
    FROM sys_menu
    INNER JOIN sys_menu_role 
        ON sys_menu.id = sys_menu_role.id_menu
    WHERE sys_menu_role.group_id = ?
      AND sys_menu.url = ?
");
$stmt->execute([$_SESSION['level'], $path_url]);

if ($role = $stmt->fetch(PDO::FETCH_OBJ)) {
    $role_act = [
        'read_act'   => $role->read_act,
        'insert_act' => $role->insert_act,
        'up_act'     => $role->update_act,
        'del_act'    => $role->delete_act
    ];
}

/* =========================
   OBJECT TO ARRAY (SAFE)
========================= */
function toArray($data)
{
    if (is_object($data)) {
        $data = (array) $data;
    }

    if (is_array($data)) {
        return array_map('toArray', $data);
    }

    return $data;
}
