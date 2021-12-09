<?php 
    $pageTitle ="Login | Twitter";
    include_once "backend/shared/header.php";

?>

<section class="signup-container">
    <form method="post">
        <h1>Login into Twitter</h1>
        <div class="form-group">
            <label for="name">username or Email</label>
            <input type="text" name="username" placeholder="Enter Your Email or username" id="name" required="required" autocomplete="off">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" name="password" id="password" placeholder="Enter Your password" required='required' autocomplete="off">
            <a href="#">Forget Password?</a>
            <i class="fa fa-eye pass1"></i>
        </div>
        <div class="form-group">
            <button type="submit" class="btn-signup">Login</button>
        </div>
        <div class="form-group">
        <p>Don't Have an Account ? <a href="signup.php"> Sign up</a></p>
        </div>
    </form>
</section>
<script src="frontend/assets/js/showpassword.js"></script>
</body>
</html>
