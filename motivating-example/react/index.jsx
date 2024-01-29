import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom";

function BlogDetail(props) {
  const [content, setContent] = useState();
  const [mode, setMode] = useState("CODE");

  useEffect(() => {
    fetch("/getBlog")
      .then((res) => res.json())
      .then((data) => setContent(data));
  }, []);

  return (
    <>
      <button onClick={() => setMode("HTML")} />
      <BlogContent
        mode={mode}
        content={content}
        processContent={props.processContent}
      />
    </>
  );
}

function BlogContent(props) {
  const [html, setHtml] = useState();

  useEffect(() => {
    setHtml(
      props.mode === "HTML"
        ? sanitize(props.content)
        : props.processContent(props.content)
    );
  }, [props.mode, props.content]);

  if (props.mode === "HTML") {
    // the sink is dangerouslySetInnerHTML
    return <p dangerouslySetInnerHTML={{ __html: html }} />;
  }
}

ReactDOM.render(
  <BlogDetail processContent={(v) => v} />,
  document.getElementById("root")
);
