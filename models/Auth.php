<?php

require_once 'dao/UserDaoMysql.php';

class Auth{

    private $pdo;
    private $base;

    public function __construct(PDO $pdo, $base){
        $this->pdo = $pdo;
        $this->base = $base;
    }

    public function checkToken(){ // Função que verifica na sessão se o token pertence a algum usuário
        if(!empty($_SESSION['token'])){
            $token = $_SESSION['token'];

            $userDao = new UserDaoMysql($this->pdo);
            $user = $userDao->findByToken($token);

            if($user){
                return $user;
            }
        }

        header("Location: ".$this->base."/login.php");
        exit;
    }

    public function validateLogin($email, $password){
        $userDao = new UserDaoMysql($this->pdo); // Chama o DAO para consultas no BD

        $user = $userDao->findByEmail($email); // Verifica e retorna o usuário, caso o email exista

        if($user){

            if(password_verify($password, $user->password)){ // Verifica se a senha está correta

                $token = md5(time().rand(0, 9999)); // Gera um token

                $_SESSION['token'] = $token; // Grava o token na sessão
                $user->token = $token; // Atribui o token ao usuário
                $userDao->update($user); // Atualiza o usuário com o token no banco de dados

                return true;
            } 
                
        }

        return false;
    }

    public function emailExists($email){
        $userDao = new UserDaoMysql($this->pdo);
        return $userDao->findByEmail($email) ? true : false;
    }

    public function registerUser($name, $email, $password, $birthdate){
        $userDao = new UserDaoMysql($this->pdo);

        $token = md5(time().rand(0,9999));

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $newUser = new User();
        $newUser->name = $name;
        $newUser->email = $email;
        $newUser->password = $hash;
        $newUser->birthdate = $birthdate;
        $newUser->token = $token;

        $userDao->insert($newUser);

        $_SESSION['token'] = $token;
    }

}