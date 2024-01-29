const router = require("express").Router();
const Blog = require("mongoose").model("Blog");

router.post("/addBlog", async (req, res, next) => {
  // req is the source, adversary-controlled request
  await Blog.create({ content: req.body.content });
});

router.get("/getBlog", async (req, res, next) => {
  const blog = await Blog.findOne().exec();
  return res.send(blog.content);
});
