<?php
	if (isset($_POST["submit"])){
		$username = (string)$_POST["username"];
		$password = (string)$_POST["password"];
		
		if ($username === "admin" && $password==="admin"){
			setcookie("admin", "1", time()+1800);
			header("location: update.php");
			exit();
		}
	}
	
?>
<!doctype html>
<html>
<!-- Latest compiled and minified CSS -->
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
<head>

	<style>
	html{
		width:100%;
		height:100%;
	}
	* {
		padding:0;
		margin:0;
	}	
	header{
		height:30px;
		width:100%;
		line-height:30px;
		background: #f3f3f3;
		text-align:center;
	}
	#main{
		width: 600px;
		margin:0 auto;
	}
	</style>
</head>
<body>
	<header>Powered by PotatoSec</header>
	<div id="main">
		<h2>Authorization Required</h2>
		<p>Please enter your username and password.</p>
		<?php if (isset($_POST["submit"])){ ?>
			<div class="alert alert-danger">
			  <strong>Danger!</strong> Indicates a dangerous or potentially negative action.
			</div>
		<?php } ?> 
		<form action="" method="post">
			<div class="form-group">
				<label for="exampleInputUsername">Username</label>
				<input type="text" name="username" class="form-control" id="exampleInputusername" placeholder="Enter username">
			  </div>
			  <div class="form-group">
				<label for="exampleInputPassword1">Password</label>
				<input type="password" name="password" class="form-control" id="exampleInputPassword1" placeholder="Password">
			  </div>
			  <button type="submit" name="submit" class="btn btn-primary">Submit</button>
		</form>
		</div>
</body>
</html>
