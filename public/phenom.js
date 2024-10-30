var t = ["x", "y", "z"], e = function(t2) {
  Object.assign(this, {uniforms: {}, geometry: {vertices: [{x: 0, y: 0, z: 0}]}, mode: 0, modifiers: {}, attributes: [], multiplier: 1, buffers: []}), Object.assign(this, t2), this.prepareProgram(), this.prepareUniforms(), this.prepareAttributes();
};
e.prototype.compileShader = function(t2, e2) {
  var i2 = this.gl.createShader(t2);
  return this.gl.shaderSource(i2, e2), this.gl.compileShader(i2), i2;
}, e.prototype.prepareProgram = function() {
  var t2 = this.gl, e2 = this.vertex, i2 = this.fragment, r = t2.createProgram();
  t2.attachShader(r, this.compileShader(35633, e2)), t2.attachShader(r, this.compileShader(35632, i2)), t2.linkProgram(r), t2.useProgram(r), this.program = r;
}, e.prototype.prepareUniforms = function() {
  for (var t2 = Object.keys(this.uniforms), e2 = 0; e2 < t2.length; e2 += 1) {
    var i2 = this.gl.getUniformLocation(this.program, t2[e2]);
    this.uniforms[t2[e2]].location = i2;
  }
}, e.prototype.prepareAttributes = function() {
  this.geometry.vertices !== void 0 && this.attributes.push({name: "aPosition", size: 3}), this.geometry.normal !== void 0 && this.attributes.push({name: "aNormal", size: 3}), this.attributeKeys = [];
  for (var t2 = 0; t2 < this.attributes.length; t2 += 1)
    this.attributeKeys.push(this.attributes[t2].name), this.prepareAttribute(this.attributes[t2]);
}, e.prototype.prepareAttribute = function(e2) {
  for (var i2 = this.geometry, r = this.multiplier, s = i2.vertices, n = i2.normal, a = new Float32Array(r * s.length * e2.size), o = 0; o < r; o += 1)
    for (var h = e2.data && e2.data(o, r), u = o * s.length * e2.size, f = 0; f < s.length; f += 1)
      for (var c = 0; c < e2.size; c += 1) {
        var l = this.modifiers[e2.name];
        a[u] = l !== void 0 ? l(h, f, c, this) : e2.name === "aPosition" ? s[f][t[c]] : e2.name === "aNormal" ? n[f][t[c]] : h[c], u += 1;
      }
  this.attributes[this.attributeKeys.indexOf(e2.name)].data = a, this.prepareBuffer(this.attributes[this.attributeKeys.indexOf(e2.name)]);
}, e.prototype.prepareBuffer = function(t2) {
  var e2 = t2.data, i2 = t2.name, r = t2.size, s = this.gl.createBuffer();
  this.gl.bindBuffer(34962, s), this.gl.bufferData(34962, e2, 35044);
  var n = this.gl.getAttribLocation(this.program, i2);
  this.gl.enableVertexAttribArray(n), this.gl.vertexAttribPointer(n, r, 5126, false, 0, 0), this.buffers[this.attributeKeys.indexOf(t2.name)] = {buffer: s, location: n, size: r};
}, e.prototype.render = function(t2) {
  var e2 = this, i2 = this.uniforms, r = this.multiplier, s = this.gl;
  s.useProgram(this.program);
  for (var n = 0; n < this.buffers.length; n += 1) {
    var a = this.buffers[n], o = a.location, h = a.buffer, u = a.size;
    s.enableVertexAttribArray(o), s.bindBuffer(34962, h), s.vertexAttribPointer(o, u, 5126, false, 0, 0);
  }
  Object.keys(t2).forEach(function(e3) {
    i2[e3].value = t2[e3].value;
  }), Object.keys(i2).forEach(function(t3) {
    var r2 = i2[t3];
    e2.uniformMap[r2.type](r2.location, r2.value);
  }), s.drawArrays(this.mode, 0, r * this.geometry.vertices.length), this.onRender && this.onRender(this);
}, e.prototype.destroy = function() {
  for (var t2 = 0; t2 < this.buffers.length; t2 += 1)
    this.gl.deleteBuffer(this.buffers[t2].buffer);
  this.gl.deleteProgram(this.program), this.gl = null;
};
var i = function(t2) {
  var e2 = this, i2 = t2 || {}, r = i2.canvas;
  r === void 0 && (r = document.querySelector("canvas"));
  var s = i2.context;
  s === void 0 && (s = {});
  var n = i2.contextType;
  n === void 0 && (n = "experimental-webgl");
  var a = i2.settings;
  a === void 0 && (a = {});
  var o = r.getContext(n, Object.assign({alpha: false, antialias: false}, s));
  Object.assign(this, {gl: o, canvas: r, uniforms: {}, instances: new Map(), shouldRender: true}), Object.assign(this, {devicePixelRatio: 1, clearColor: [1, 1, 1, 1], position: {x: 0, y: 0, z: 2}, clip: [1e-3, 100]}), Object.assign(this, a), this.uniformMap = {float: function(t3, e3) {
    return o.uniform1f(t3, e3);
  }, vec2: function(t3, e3) {
    return o.uniform2fv(t3, e3);
  }, vec3: function(t3, e3) {
    return o.uniform3fv(t3, e3);
  }, vec4: function(t3, e3) {
    return o.uniform4fv(t3, e3);
  }, mat2: function(t3, e3) {
    return o.uniformMatrix2fv(t3, false, e3);
  }, mat3: function(t3, e3) {
    return o.uniformMatrix3fv(t3, false, e3);
  }, mat4: function(t3, e3) {
    return o.uniformMatrix4fv(t3, false, e3);
  }}, o.enable(o.DEPTH_TEST), o.depthFunc(o.LEQUAL), o.getContextAttributes().alpha === false && (o.clearColor.apply(o, this.clearColor), o.clearDepth(1)), this.onSetup && this.onSetup(o), window.addEventListener("resize", function() {
    return e2.resize();
  }), this.resize(), this.render();
};
i.prototype.resize = function() {
  var t2 = this.gl, e2 = this.canvas, i2 = this.devicePixelRatio, r = this.position;
  e2.width = e2.clientWidth * i2, e2.height = e2.clientHeight * i2;
  var s = t2.drawingBufferWidth, n = t2.drawingBufferHeight, a = s / n;
  t2.viewport(0, 0, s, n);
  var o = Math.tan(Math.PI / 180 * 22.5), h = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, r.x, r.y, (a < 1 ? 1 : a) * -r.z, 1];
  this.uniforms.uProjectionMatrix = {type: "mat4", value: [0.5 / o, 0, 0, 0, 0, a / o * 0.5, 0, 0, 0, 0, -(this.clip[1] + this.clip[0]) / (this.clip[1] - this.clip[0]), -1, 0, 0, -2 * this.clip[1] * (this.clip[0] / (this.clip[1] - this.clip[0])), 0]}, this.uniforms.uViewMatrix = {type: "mat4", value: [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]}, this.uniforms.uModelMatrix = {type: "mat4", value: h};
}, i.prototype.toggle = function(t2) {
  t2 !== this.shouldRender && (this.shouldRender = t2 !== void 0 ? t2 : !this.shouldRender, this.shouldRender && this.render());
}, i.prototype.render = function() {
  var t2 = this;
  this.gl.clear(16640), this.instances.forEach(function(e2) {
    e2.render(t2.uniforms);
  }), this.onRender && this.onRender(this), this.shouldRender && requestAnimationFrame(function() {
    return t2.render();
  });
}, i.prototype.add = function(t2, i2) {
  i2 === void 0 && (i2 = {uniforms: {}}), i2.uniforms === void 0 && (i2.uniforms = {}), Object.assign(i2.uniforms, JSON.parse(JSON.stringify(this.uniforms))), Object.assign(i2, {gl: this.gl, uniformMap: this.uniformMap});
  var r = new e(i2);
  return this.instances.set(t2, r), r;
}, i.prototype.remove = function(t2) {
  var e2 = this.instances.get(t2);
  e2 !== void 0 && (e2.destroy(), this.instances.delete(t2));
}, i.prototype.destroy = function() {
  var t2 = this;
  this.instances.forEach(function(e2, i2) {
    e2.destroy(), t2.instances.delete(i2);
  }), this.toggle(false);
};
export default i;

