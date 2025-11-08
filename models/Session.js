import { Schema, model } from "mongoose";

const sessionSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
}, {
    timestamps: true
});

const Session = model('Session', sessionSchema);
export default Session;