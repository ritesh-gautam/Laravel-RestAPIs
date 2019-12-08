<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;


class AuthController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        return response()->json(compact('token'));
    }

    public function register(Request $request)
    {
            $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if($validator->fails()){
                return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json(compact('user','token'),201);
    }


    public function userinfo(Request $request){


        $reuestInfo = $request->all();
        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                    return response()->json(['user_not_found'], 404);
            }
            return response()->json(compact('user'),201);

        }catch(Exception $e){
            $error = $e->getMessage();
            return response()->json(compact('error'),404);
        }

    } 
    public function logout(Request $request)
    {
        try{
            
            $api_token = $request->bearerToken();
            JWTAuth::setToken($api_token)->invalidate();
            return response()->json([
                'status' => 'success',
                'status_code' => 201,
                'message' => 'Logout successful!',
            ], 201);
        }catch(JWTException $e){

            $error =  $e->getMessage();
            return response()->json(compact('error'),404);
        }
    }
     
}