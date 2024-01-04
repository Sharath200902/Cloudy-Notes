const express = require('express');
const router = express.Router();
const fetchuser = require('../middleware/fetchuser');
const Note = require('../models/Note');
const { body, validationResult } = require('express-validator');

//ROUTE-1 : get all the notes of a user using: GET "/api/auth/fetchallnotes". Login required.
router.get('/fetchallnotes', fetchuser, async (req,res)=>{
    try {
    const notes = await Note.find({user : req.user.id});
    res.json(notes);     
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Some error occurred");
    }
})
//ROUTE-2 : add a new note using: POST "/api/auth/addnote". Login required.
router.post('/addnote', fetchuser, [
    body('title', 'enter a valid title').isLength({min:3}),
    body('description', 'description must be atleast 8 characters').isLength({min:8}),
    
], async (req,res)=>{
    
    try {
    const{title, description, tag} = req.body;
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }

    const note = new Note({
        title, description, tag, user: req.user.id 
    })

    const savedNote = await note.save()

    
    res.json(savedNote);   
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Some error occurred");
    }
})

module.exports = router