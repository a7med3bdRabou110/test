<?php 

    class Account {
        private $pdo ;
        private $errorArray = array();

        //Connect to database
        public function __construct()
        {
            $this->pdo = Database::instance();
        }

        public function register($fn , $ln  , $un , $em , $pass , $pass2){
            $this->validateFirstName($fn);
            $this->validateLastName($ln);
            $this->validateEmail($em);
            $this->validatePasswords($pass,$pass2);
            if(empty($this->errorArray)){
                return $this->insertUserDetails($fn,$ln,$un,$em,$pass);
            }else{
                return false ;
            }
        }

        private function validateFirstName($fn){
            if($this->length($fn , 2, 25)){
                array_push($this->errorArray , Constants::$firstNameCharacter);
            }
        }


        private function validateLastName($ln){
            if($this->length($ln,2,25)){
                array_push($this->errorArray,Constants::$lastNameCharacter);
            }
        }

        public function generateUsername($fn,$ln){
            if(!empty($fn) && !empty($ln)) {
                if(!in_array(Constants::$firstNameCharacter, $this->errorArray) && !in_array(Constants::$lastNameCharacter,$this->errorArray)){
                    $username = strtolower($fn ."" .$ln);
                    if($this->checkUsernameExist($username)){
                        $screenRand = rand();
                        $userLink = "".$username."".$screenRand ; 
                    }else {
                        $userLink = $username ; 
                    }
                    return $userLink ;
                }
            }
        }

        private function checkUsernameExist($username){
            $stmt = $this->pdo->prepare("SELECT username FROM users WHERE username = :username");
            $stmt->bindParam(":username",$username);
            $stmt->execute();
            $count = $stmt->rowCount();
            if($count > 0) {
                return true;
            }else{
                return false;
            }
        }

        private function validateEmail($em) {
            $stmt = $this->pdo->prepare("SELECT email FROM users WHERE email=:email");
            $stmt->bindParam(":email",$em,PDO::PARAM_STR);
            $stmt->execute();
            $count = $stmt->rowCount();
            if($count != 0) {
                array_push($this->errorArray,Constants::$emailtaken);
            }

            if(!filter_var($em , FILTER_VALIDATE_EMAIL)){
                array_push($this->errorArray, Constants::$emailInValid);
            }
        }

        private function validatePasswords($pass,$pass2){
            if($pass != $pass2){
                array_push($this->errorArray,Constants::$passwordDoNotMatch);
            }

            if($this->length($pass , 7 , 25)){
                array_push($this->errorArray,Constants::$passwordTooShort);
            }

            if($this->length($pass2 , 7 , 25)){
                array_push($this->errorArray,Constants::$passwordTooShort);
            }

            if(!preg_match("/[A-Za-z0-9@#$%&* ]/",$pass)){
                array_push($this->errorArray,Constants::$passwordNotAlphNumber);
            }
        }

        private function insertUserDetails($fn,$ln,$un,$em,$pass){
            $pass_hash = password_hash($pass,PASSWORD_BCRYPT);
            $rand =rand(0,2);
            if($rand==0){
                $profilePic = "frontend/assets/images/defaultProfilePic.png";
                $profileCover = "frontend/assets/images/backgroundCoverPic.svg";
            }else if($rand == 1) {
                $profilePic = "frontend/assets/images/defaultPic.svg";
                $profileCover = "frontend/assets/images/backgroundImage.svg";
            }else if($rand == 2){
                $profilePic = "frontend/assets/images/avatar.png";
                $profileCover = "frontend/assets/images/backgroundCoverPic.svg";
            }
            $stmt = $this->pdo->prepare("INSERT INTO users(firstName,lastName,username,email,password,profileImage,profileCover) VALUES (:fn,:ln,:un,:em,:pw,:pic,:cov)");
            $stmt->bindParam(':fn', $fn, PDO::PARAM_STR);
            $stmt->bindParam(':ln', $ln, PDO::PARAM_STR);
            $stmt->bindParam(':un', $un, PDO::PARAM_STR);
            $stmt->bindParam(':em', $em, PDO::PARAM_STR);
            $stmt->bindParam(':pw', $pass_hash, PDO::PARAM_STR);
            $stmt->bindParam(':pic', $profilePic, PDO::PARAM_STR);
            $stmt->bindParam(':cov', $profileCover, PDO::PARAM_STR);
            echo "<pre>";
            var_dump($stmt);
            echo "</pre>";
            // $stmt->execute();
            // return $this->pdo->lastInsertId();
        }

        private function length($input , $min ,$max) {
            if(strlen($input) < $min){
                return true;
            }else if(strlen($input) > $max){
                return true;
            }
        }


        //Get Errors
        public function getError($error){
            if(in_array($error,$this->errorArray)){
                return "<span class='errorMessage'>$error</span>";
            }
        }
    }