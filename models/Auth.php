<?php

require_once 'dao/UserDaoMysql.php';

class Auth{

    private $pdo;
    private $base;
    private $dao;

    public function __construct(PDO $pdo, $base){
        $this->pdo = $pdo;
        $this->base = $base;
        $this->dao = new UserDaoMysql($this->pdo);
    }

    public function checkToken(){ // Função que verifica na sessão se o token pertence a algum usuário
        if(!empty($_SESSION['token'])){
            $token = $_SESSION['token'];

            $user = $this->dao->findByToken($token);

            if($user){
                return $user;
            }
        }

        header("Location: ".$this->base."/login.php");
        exit;
    }

    public function validateLogin($email, $password){
        $user = $this->dao->findByEmail($email); // Verifica e retorna o usuário, caso o email exista

        if($user){

            if(password_verify($password, $user->password)){ // Verifica se a senha está correta

                $token = md5(time().rand(0, 9999)); // Gera um token

                $_SESSION['token'] = $token; // Grava o token na sessão
                $user->token = $token; // Atribui o token ao usuário
                $this->dao->update($user); // Atualiza o usuário com o token no banco de dados

                return true;
            } 
                
        }

        return false;
    }

    public function emailExists($email){
        return $this->dao->findByEmail($email) ? true : false;
    }

    public function registerUser($name, $email, $password, $birthdate){

        $token = md5(time().rand(0,9999));

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $newUser = new User();
        $newUser->name = $name;
        $newUser->email = $email;
        $newUser->password = $hash;
        $newUser->birthdate = $birthdate;
        $newUser->token = $token;

        $this->dao->insert($newUser);

        $_SESSION['token'] = $token;
    }

}