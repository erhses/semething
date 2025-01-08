import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt"
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken"
import cors from 'cors'
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js"
import { populate } from "dotenv";

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password


const server = express();
let PORT = 3000;

server.use(express.json());
server.use(cors())

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(token == null){
        return res.status(401).json({"error" : "Unauthorized"})
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if(err){
            return res.status(403).json({"error" : "Invalid Token"})
        }
        req.user = user.id
        next()
    })
}

const verifyOptionalJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        // No token provided, treat as anonymous user
        req.user = null;
        return next();
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, decoded) => {
        if (err) {
            req.user = null;
        } else {
            req.user = decoded.id;
        }
        next();
    });
};

const formatDatatoSend= (user) => {

    const accessToken = jwt.sign({id: user._id}, process.env.SECRET_ACCESS_KEY)

    return{
        accessToken,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        name: user.personal_info.name,
        isAdmin: user.isAdmin
    }
}

const generateUsername = async (email) => {
    let username = email.split("@")[0];

    let usernameExists = await User.exists({"personal_info.username" : username}).then((result) => result)

    usernameExists ? username += nanoid().substring(0, 4) : "";
    return username
}

server.post("/signup", (req, res) => {
    let { name, email, password, isAdmin } = req.body; // Accept `isAdmin` in the request body

    if (!email.length) {
        return res.status(403).json({ error: "Enter email" });
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ error: "Email invalid" });
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "Password too short or long (1 Upper, 1 Lower, 1 numeric)" });
    }

    bcrypt.hash(password, 10, async (err, hashed_pwd) => {
        let username = await generateUsername(email);

        let user = new User({
            personal_info: { name, email, password: hashed_pwd, username },
            isAdmin: isAdmin || false
        });

        user.save().then((u) => {
            return res.status(200).json(formatDatatoSend(u));
        })
        .catch(err => {
            if (err.code == 11000) {
                return res.status(500).json({ "error": "Email already exists" });
            }
        });
    });
});


server.post('/signin', (req, res) => {
    let {email, password} = req.body

    User.findOne({"personal_info.email" : email})
    .then((user) => {
        if(!user){
            return res.status(403).json({"error" : "Email not found"})
        }

        bcrypt.compare(password, user.personal_info.password, (err, result) => {
            if(err){
                return res.status(403).json({"error": "Pleasae try again later"})
            }
            if(!result){
                return res.status(403).json({"error" : "Incorrect Password"})
            } else{
                return res.status(200).json(formatDatatoSend(user))
            }
        })
    })
    .catch((err) => {
        return res.status(500).json({"error" : err.message})
    })
})



server.post('/latest-blogs', (req, res) =>{
    const maxLimit = 3
    let {page} = req.body


    // Blog.find({draft: false})
    Blog.find({draft: false, status: "published"})
    .populate("author", "personal_info.name personal_info.profile_img personal_info.username -_id")
    .sort({"publishedAt": -1})
    .select("blog_id title des activity tags publishedAt -_id")
    .skip((page-1)*maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({blogs})
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
})

server.post('/all-latest-blogs-count', (req, res) => {
    Blog.countDocuments({draft: false, status: "published"})
    .then(count => {
        return res.status(200).json({totalDocs: count})
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
})

server.get('/trending-blogs', (req, res) =>{

    Blog.find({draft: false, status: "published"})
    .populate("author", "personal_info.name personal_info.profile_img personal_info.username -_id")
    .sort({"activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1})
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs => {
        return res.status(200).json({blogs})
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
})

server.post('/search-blogs', (req, res) => {
    let { tag, query, page, author, limit, eliminate_blog, status } = req.body;
    let findQuery = { draft: false, status: "published" }; 

    if (status) {
        findQuery.status = status; 
    }

    if (tag) {
        findQuery.tags = tag;
        findQuery.blog_id = { $ne: eliminate_blog };
    } else if (query) {
        findQuery.title = new RegExp(query, 'i');
    } else if (author) {
        findQuery.author = author;
    }

    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
        .populate("author", "personal_info.name personal_info.profile_img personal_info.username -_id")
        .sort({ createdAt: -1 })
        .select("blog_id title des activity tags publishedAt state -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});

server.post('/search-blogs-count', (req, res) => {
    let { tag, query, author, status } = req.body;
    let findQuery = { draft: false, status: "published" }; 

    if (status) {
        findQuery.status = status;
    }

    if (tag) {
        findQuery.tags = tag;
    } else if (query) {
        findQuery.title = new RegExp(query, 'i');
    } else if (author) {
        findQuery.author = author;
    }

    Blog.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});


server.post('/search-users', (req, res) => {
    let {query} = req.body

    User.find({"personal_info.username": new RegExp(query, 'i')})
    .limit(15)
    .select("personal_info.name personal_info.profile_img personal_info.username -_id")
    .then(users => {
        return res.status(200).json({users})
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
})

server.post('/get-profile', (req, res) => {
    let {username} = req.body
    User.findOne({"personal_info.username": username})
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then(user => {
        return res.status(200).json(user)
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
})

server.post('/create-blog', verifyJWT, (req, res) => {
        let authorID = req.user; 
        let { title, des, tags, content, draft, status, id } = req.body;
        
        if (!title || !title.trim()) {
            return res.status(400).json({ error: "Title is required" });
        }
        if(!draft){
            if (!des || des.length > 200) {
                return res.status(400).json({ error: "Description is required and should not exceed 200 characters" });
            }
            if(!content.length){
                return res.status(400).json({error: "Content is required"})
            }
            if(!tags.length || tags.length > 5){
                return res.status(400).json({error: "Tags are required"})
            }
        }
        tags = tags.map(tag => tag.toLowerCase())
        let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim()+nanoid()

        if(id){
            Blog.findOneAndUpdate({blog_id}, {title, des, content, tags, draft: draft ? draft : false})
            .then(() => {
                return res.status(200).json({id: blog_id})
            })
            .catch(err=>{
                return res.status(500).json({error: err.message})
            })

        }else {
            
            let blog = new Blog({
                title, des, content, tags, author: authorID, blog_id, draft: Boolean(draft), status
            })
    
            blog.save().then(blog =>{
                let incrementVal = draft ? 0 : 1
                User.findOneAndUpdate({_id: authorID}, {$inc: {"account_info.total_posts": incrementVal}, $push: {"blogs": blog._id}})
                .then(() => {
                    return res.status(200).json({id: blog.blog_id})
                })
                .catch(err => {
                    return res.status(500).json({error: err.message})
                })
            })
            .catch(err => {
                return res.status(500).json({error: err.message})
            })
        }

});


server.post('/get-blog', (req, res) => {
    let { blog_id, draft, mode } = req.body;
    let incrementVal = mode != 'edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": incrementVal } }, { new: true })
        .populate("author", "personal_info.name personal_info.username personal_info.profile_img")
        .select("title des content activity publishedAt blog_id tags author")
        .then(blog => {
            if (!blog) {
                return res.status(404).json({ error: "Blog not found" });
            }

            if (!blog.author) {
                return res.status(404).json({ error: "Author not found" });
            }

            if (incrementVal) {
                User.findOneAndUpdate(
                    { _id: blog.author },
                    { $inc: { "account_info.total_reads": incrementVal, "account_info.reputation_points": 1 } }
                ).catch(err => console.error(err));
            }

            if (blog.draft && !draft) {
                return res.status(403).json({ error: "Can't access draft" });
            }

            return res.status(200).json({ blog });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});


server.post('/like-blog', verifyOptionalJWT, async (req, res) => {
    const user_id = req.user;
    const { _id, isLiked } = req.body;
    const incrementVal = !isLiked ? 1 : -1;

    try {
        const blog = await Blog.findOneAndUpdate(
            { _id },
            { $inc: { "activity.total_likes": incrementVal } },
            { new: true }
        );

        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        if (!user_id) {
            // Anonymous users, no notification or reputation update
            return res.status(200).json({ liked: !isLiked, total_likes: blog.activity.total_likes });
        }

        // Update author's reputation points for like/unlike
        await User.findOneAndUpdate(
            { _id: blog.author },
            { $inc: { "account_info.reputation_points": incrementVal * 2 } }
        );

        if (!isLiked) {
            // Create a notification for logged-in users
            const like = new Notification({
                type: "like",
                blog: _id,
                notification_for: blog.author,
                user: user_id,
            });
            await like.save();
        } else {
            await Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" });
        }

        return res.status(200).json({ liked: !isLiked, total_likes: blog.activity.total_likes });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "An error occurred while liking the blog." });
    }
});

  

server.post('/is-liked-by-user', verifyOptionalJWT, (req, res) =>{
    let user_id = req.user
    let {_id} = req.body

    Notification.exists({user: user_id, type: 'like', blog: _id})
    .then(result => {
        return res.status(200).json({result})
    })
    .catch(err =>{
        return res.status(500).json({error: err.message})
    })

})


server.post('/add-comment', verifyJWT, (req, res) => {
    let user_id = req.user
    let{_id, comment, blog_author, replying_to} = req.body

    if(!comment.length){
        return res.status(403).json({error: "write something"})
    }

    let commentObj = {
        blog_id: _id,
        blog_author,
        comment, 
        commented_by: user_id,
    }

    if(replying_to){
        commentObj.parent = replying_to
    }

    new Comment(commentObj).save().then(async commentFile => {
        let {comment, commentedAt, children} = commentFile
        Blog.findOneAndUpdate({_id}, {$push: {"comments": commentFile._id}, $inc: {"activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 }})
        .then(blog => {
            console.log("new comment")
        })

        let notificationObj = {
            type: replying_to ? "reply" : "comment",
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: commentFile._id
        }

        if(replying_to){
            notificationObj.replied_on_comment = replying_to
            await Comment.findOneAndUpdate({_id: replying_to}, {$push: {children: commentFile._id}})
            .then(replyingToCommentDoc => {notificationObj.notification_for =replyingToCommentDoc.commented_by })

        }

        new Notification(notificationObj).save().then(notification => console.log("uyyu"))

        return res.status(200).json({
            comment, commentedAt, _id: commentFile._id, user_id, children
        })
    })
})


server.post('/get-blog-comments', (req, res) => {
    let {blog_id, skip} = req.body
    let maxLimit = 15
    Comment.find({blog_id, isReply: false})
    .populate("commented_by", "personal_info.username personal_info.name personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({
        'commentedAt': -1
    })
    .then(comment => {
        return res.status(200).json(comment)
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
})

server.post('/get-replies', (req,res) => {
    let {_id, skip} = req.body

    let maxLimit = 5
    Comment.findOne({_id})
    .populate({
        path: "children",
        options: {
            limit: maxLimit,
            skip: skip,
            sort: {'commentedAt': -1}
        },
        populate: {
            path: 'commented_by',
            select: 'personal_info.profile_img personal_info.name personal_info.username'
        },
        select: "-blog_id -updatedAt"
    })
    .select("children")
    .then(doc => {
        return res.status(200).json({replies: doc.children})
    })
    .catch(err => {
        return res.status(500).json({error: err.message})
    })
})

server.post('/get-salary', verifyJWT, async (req, res) => {
    const userId = req.user;

    try {
        const user = await User.findById(userId).select("account_info.salary");
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({ salary: user.account_info.salary });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "An error occurred while fetching salary." });
    }
});

server.post('/get-all-blogs', async (req, res) => {
    try {
      const pendingBlogs = await Blog.find({ draft: false, status: "pending" }).populate("author", "personal_info.name  personal_info.username -_id")
      .select("blog_id title des activity tags publishedAt -_id");
      const publishedBlogs = await Blog.find({ draft: false, status: "published" }).populate("author", "personal_info.name  personal_info.username -_id")
      .select("blog_id title des activity tags publishedAt -_id");
      res.status(200).json({ pendingBlogs, publishedBlogs });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  server.post('/approve-blog', (req, res) => {
    const { blog_id } = req.body;
  
    if (!blog_id) {
      return res.status(400).json({ error: "Blog ID is required" });
    }
  
    Blog.findOneAndUpdate({ blog_id }, { status: "published" }, { new: true })
      .then(updatedBlog => {
        if (!updatedBlog) {
          return res.status(404).json({ error: "Blog not found" });
        }
        return res.status(200).json({ message: "Blog approved successfully", blog: updatedBlog });
      })
      .catch(err => {
        console.error("Error approving blog:", err);
        return res.status(500).json({ error: "Failed to approve blog" });
      });
  });
  
  server.post('/delete-blog', (req, res) => {
    const { blog_id } = req.body;
  
    if (!blog_id) {
      return res.status(400).json({ error: "Blog ID is required" });
    }
  
    Blog.findOneAndDelete({ blog_id })
      .then(deletedBlog => {
        if (!deletedBlog) {
          return res.status(404).json({ error: "Blog not found" });
        }
        return res.status(200).json({ message: "Blog deleted successfully", blog: deletedBlog });
      })
      .catch(err => {
        console.error("Error deleting blog:", err);
        return res.status(500).json({ error: "Failed to delete blog" });
      });
  });
  
      


server.listen(PORT, () => {
  console.log("listening on " + PORT);
});