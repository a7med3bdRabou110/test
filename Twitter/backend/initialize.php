<?php 
    ob_start();
    //set_timezone
    date_default_timezone_set("Africa/Cairo");

    //include database class
    
    // include("./classes/database.php");
    spl_autoload_register(function($class){
        require_once "classes/$class.php";
    });
    
    define("DB_HOST","localhost");
    define("DB_NAME","twitter");
    define("DB_USER","ahmed");
    define("DB_PASS","AHMED110@");
    

    //To get dynamic link
    $public_end = strpos($_SERVER["SCRIPT_NAME"],"/frontend/")+9 ; 
    $doc_root = substr($_SERVER["SCRIPT_NAME"],0,$public_end);
    define("WWW_ROOT",$doc_root);
    // echo WWW_ROOT;






    //initalize class
    $account = new Account;
