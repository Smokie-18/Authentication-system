import mongoose from 'mongoose'
import { refreshTokenHandler } from '../controllers/auth.controller.js'


const sessionSchema = new mongoose.Schema({

    user :{
        type : mongoose.Schema.Types.ObjectId,
        ref : "users" ,
        required : [true , "User is required ."]
    },

    refreshTokenHash :{
        type : String ,
        required : [true , "Refresh token is required "]

    },

      ip :{
        type : String ,
        required : [true , "IP address is required "]

    },
       userAgent :{
        type : String ,
        required : [true , "User agent is required "]

    },
      revoked :{
        type : Boolean ,
        default : false ,

    },


} ,{timstamps :true})



const sessionModel = mongoose.model("sessions" , sessionSchema)
export default sessionModel 