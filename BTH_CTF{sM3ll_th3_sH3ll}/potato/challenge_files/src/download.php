<?php

include "secret.php";

if (!isset($_COOKIE["admin"])){
	header("location: login.php");
	exit();		
}


if (isset($_GET["type"]) && $_GET["type"] === "firmware"){
	header ('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename=firmware.bin');
	echo $firmware;
}else{
	header ('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename=firmware.sig');
	echo hash("sha512", $SALT . $firmware);
}
