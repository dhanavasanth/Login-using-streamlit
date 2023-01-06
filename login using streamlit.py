import streamlit as st
import re

#To check the userID is valid

def user_validation(user):
    to_pass = "^[a-z0-9A-Z]+[\.]?[a-zA-Z0-9]+[@]\w+[.]\w{2,3}$"
    result_1 = re.search(to_pass , user)
    if (result_1):
        return True

#To check the password is valid

def password_validation(password):
    to_pass = "^.*(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*_+-])(?=.{5,16}).*$"
    result_2 = re.findall(to_pass , password)
    if (result_2):
        return True

#To check the userID and password is already registered

def user_checking(user,password):
    with open("user_information.txt","r") as data:
        for line in data:
            IN = line.split()
            if IN[0]==user and IN[1]==password:
                return True

#To register the newly given userID and password

def new_registration(user,password):
    with open("user_information.txt","a") as new_user:
        new_user.write(f'{user} {password}\n')

#To retrive password based on pre-registered userID

def forgot():
    with open("user_information.txt","r") as user_:
        for line in user_:
            INFO = line.split()
            if INFO[0]==user:
                password =  (line.split()[1:][0])
                return password
                break

#To display the menu list for user to make decisions

st.title("WELCOME TO USER LOGIN SYSTEM...")
menu = ["SIGN-IN","New Registration","Forgot Password"]
choice = st.selectbox("MENU",menu)

#It enables user to login with a pre-registered userID's

if choice=="SIGN-IN":
    user = st.text_input("USER-ID")
    password = st.text_input("PASSWORD", type = "password")
    login = st.checkbox("LOGIN")
    if (user):
        if user_validation(user)==True:
            if(password):
                if password_validation(password)==True:
                    if user_checking(user,password)==True:
                        if (login):
                            st.success("successfully logged in...")
                            st.balloons()
                    else:
                        st.error("USER-ID doesn't found ")


                else:
                    st.warning("password is invalid")
                    st.error("you can retrive your password from Forgot password")

        else:
            st.warning("user-id is invalid")

#It enables to register in a user_information document with new userID and password

if choice=="New Registration":
    user = st.text_input("ENTER NEW USER-ID")
    st.info("*USER-ID name should not start with special character and numbers")
    password = st.text_input("ENTER NEW PASSWORD", type="password")
    st.info("*PASSWORD should have minimum of 5 character , one digit , one upper and one lowercase")
    confirm_password = st.text_input("CONFIRM PASSWORD",type = "password")
    stay = st.checkbox("stay login")
    cookies = st.checkbox("I agree to taste cookies")
    if (user):
        if user_validation(user)==True:
            if (password):
                if password_validation(password)==True:
                    new_registration(user,password)
                    if confirm_password:
                        if confirm_password == password:
                            st.success("Registered successfully")
                            if (stay):
                                st.success("welcome...!"+ (user) +"..!")

                                if (cookies):
                                    st.subheader("COOKIES MADE WITH LOVE..!")
                                    st.balloons()
                                else:
                                    st.subheader("LIFE IS TOO SHORT,HAVE COOKIES AND ENJOY")
                        else:
                            st.error("PASSWORD doesn't match")
                else:
                    st.error("please enter valid PASSWORD")
        else:
            st.error("please enter valid USER-ID")

#To get the forgot password based on a pre-registered userID

if choice=="Forgot Password":
    user = st.text_input("ENTER YOUR REGISTERED USER-ID")
    GET = st.button("GET Password")
    if (user):
        if user_validation(user)==True:
            if (GET):
                if forgot():
                    st.success("your password is.."+ forgot())
        else:
            st.error("USER-ID not found please register your ID")









