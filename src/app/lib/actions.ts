"use server"

import { InputUser, PartialUser } from "./types"
import bcrypt from 'bcrypt'
import { nanoid } from 'nanoid'
import { addUser, getUserByLogin } from "./api"
import { redirect } from "next/navigation"

export const handleSignup = async (prev: unknown, data: FormData) => {

    let user: PartialUser = {
        id: nanoid(),
        name: data.get('name') as string,
        surname: data.get('surname') as string,
        login: data.get('login') as string,
        password: data.get('password') as string
    }

    const existingUserLogin = await getUserByLogin(user.login ?? "")
    if (existingUserLogin) {
        return{
            message:"Login already exists"
        }
    }

    const passRegExp = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{6,}$/

    if (user.password && !passRegExp.test(user.password)) {
        return {
            message:"Invalid password"
        }
    }

    if (user.password) {
        user.password = await bcrypt.hash(user.password, 10)
    }

    const result = addUser(user)
    console.log(result)
    redirect("/login")
}




export const handleLogin = async (prev: unknown, data: FormData) => {

    if (!data.get("login") || !data.get("password")) {
        return {
            message: "Please fill all the fields"
        }
    }

    let login = data.get('login') as string
    let password = data.get('password') as string

    const user = await getUserByLogin(login)
    if (!user) {
        return {
            message: "User not found"
        }
    }

    const match = await bcrypt.compare(password, user.password)

    if (!match) {
        return {
            message: "Passwords do not match!"
        }
    }
    console.log(user)
    redirect("/profile")

}