<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

include "secret.php";


if (!isset($_COOKIE["admin"])){
	header("location: login.php");
	exit();
}

if (!isset($_POST["submit"])){
	highlight_file('update.php');
}

if (isset($_POST["submit"])){
      $errors= array();
    
	if(!file_exists($_FILES['bin']['tmp_name']) || !is_uploaded_file($_FILES['bin']['tmp_name'])) {
		  $errors[] = "Please upload a binary";
    }

	if(!file_exists($_FILES['sig']['tmp_name']) || !is_uploaded_file($_FILES['sig']['tmp_name'])) {
		  $errors[] = "Please upload a sig";
	}


	 if(empty($errors)==true){
         $hashsum = file_get_contents($_FILES['sig']['tmp_name']);
		 $binary = file_get_contents($_FILES['bin']['tmp_name']);

		 if ($hashsum === hash("sha512", $SALT.$binary)){
			$firmware = $binary;
		 }else{
			$errors[] = "Bad signature. This has been tampered with. Refuse to upload...";
		 }
      }


}


?>
<!doctype>
<html>
<head>

</head>
<body>
<div class="alert alert-info">
	<?php
	if (isset($errors)){
		foreach($errors as $error){
			echo $error . "<br>";
		}
	}
?>
</div>
<?php loadfirmware($firmware);?>

<form action="" method="post"  enctype="multipart/form-data">
  <div class="form-group">
    <label for="exampleFormControlFile1">Signature</label>
    <input type="file" name="sig" class="form-control-file">
  </div>

  <div class="form-group">
    <label for="exampleFormControlFile1">Binary</label>
    <input type="file" name="bin" class="form-control-file"/> 
  </div>
  <button type="submit" name="submit" class="btn btn-primary">Submit</button>

</form>
</body>
<a href="download.php?type=firmware">Download installed firmware</a><br>
<a href="download.php?type=signature">Download installed signature</a>
</html>
