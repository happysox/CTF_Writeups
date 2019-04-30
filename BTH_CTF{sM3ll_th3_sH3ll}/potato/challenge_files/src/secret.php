<?php

$SALT = "monitor37";
$firmware = "echo 'Welcome to super secure router alpha 0.01'\n#Provide a neat motd for the user.\n\n#TODO Add some security checks. This script should be secure. i dunno";


function loadfirmware($exec){
	foreach(explode("\n", $exec) as $cmd){
		if (strpos($cmd, '#') !== false || strlen($cmd) == 0) {
			#SKIP
		}else{
			echo "<h2>"; 
			system($cmd);
			echo "</h2>";
	
		}
	}
	
}
