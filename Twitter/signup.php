<?php 
    include_once "backend/initialize.php";
    $pageTitle = "signUp | Twitter";
    include_once "backend/shared/header.php";
    if($_SERVER["REQUEST_METHOD"] === "POST"){
        if(isset($_POST['submit'])) {
            if(isset($_POST["fName"]) && !empty($_POST["fName"])) {
                $fName = FormSanitizer::formSanitizerName($_POST["fName"]);
                $lname = FormSanitizer::formSanitizerName($_POST["lName"]);
                $email = FormSanitizer::formSanitizerString($_POST["email"]);
                $pass  = FormSanitizer::formSanitizerString($_POST["password"]);
                $pass2 = FormSanitizer::formSanitizerString($_POST["confirm-password"]);
                $username=$account->generateUsername($fName,$lname);
                // echo $username ;
                $wasSuccessful = $account->register($fName,$lname,$username,$email,$pass,$pass2);
                if($wasSuccessful){
                    echo "data was inserted";
                }
            }
        }

    }
?>

<section class="signup-container">
    <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="POST">
        <h1>Create your Account</h1>
        <div class="form-group">
            <?php echo $account->getError(Constants::$firstNameCharacter); ?>
            <label for="fName">
                First Name
            </label>
            <input type="text" id="fName" name="fName" placeholder="Enter First Name" required="required" autocomplete="off">
        </div>
        <div class="form-group">
            <?php echo $account->getError(Constants::$lastNameCharacter); ?>
            <label for="lName">
                Last Name
            </label>
            <input type="text" id="lName" name="lName" placeholder="Enter Last Name" required="required" autocomplete="off" >
        </div>
        <div class="form-group">
        <?php echo $account->getError(Constants::$emailInValid); ?>
        <?php echo $account->getError(Constants::$emailtaken); ?>

            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="Enter your Email" required="required" autocomplete="off" >
        </div>
        <div class="form-group">
        <?php echo $account->getError(Constants::$passwordDoNotMatch); ?>
        <?php echo $account->getError(Constants::$passwordTooShort); ?>
        <?php echo $account->getError(Constants::$passwordNotAlphNumber); ?>

            <label for="password">
                Password
            </label>
            <input type="password" id="password" name="password" placeholder="Enter Your Password " required="required" autocomplete="off">
            <i class="fa fa-eye pass1"></i>
        </div>
        <div class="form-group">
            <label for="confirm-password">
                Confirm Password
            </label>
            <input type="password" name="confirm-password"  id="confirm-password" placeholder="Enter Password Repeat">
            <i class="fa fa-eye pass2"></i>
            
        </div>
        <div class="form-control">
            <input type="checkbox" name="remember" id="remeber">
            <label for="remeber">Remember Me</label>
        </div>
        <div class="form-group">
            <button type="submit" name="submit" class="btn-signup">Sign Up</button>
        </div>
        <div class="form-group">
            <p>Already Have an Account ? <a href="login.php"> Login Now</a></p>
        </div>
    </form>
</section>

    <script src="frontend/assets/js/showpassword.js"></script>

</body>
</html>